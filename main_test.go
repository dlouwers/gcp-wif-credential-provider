package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	provider = "projects/123/locations/global/workloadIdentityPools/pool/providers/k3s"
	aud      = "//iam.googleapis.com/" + provider
	image    = "europe-west4-docker.pkg.dev/proj/repo/app:v1"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }

func jwt(t *testing.T, aud any) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"aud": aud, "sub": "system:serviceaccount:ns:sa"})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(claims) + ".sig"
}

func baseRequest(t *testing.T) request {
	return request{
		APIVersion:                apiVersion,
		Kind:                      "CredentialProviderRequest",
		Image:                     image,
		ServiceAccountToken:       jwt(t, []string{aud}),
		ServiceAccountAnnotations: map[string]string{AnnotationProvider: provider},
	}
}

// fakeGoogle serves STS and IAM Credentials and records what it was sent.
type fakeGoogle struct {
	stsForm    map[string][]string
	impersonAs string
	bearer     string
	stsStatus  int
}

func (f *fakeGoogle) server(t *testing.T) endpoints {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		f.stsForm = r.PostForm
		if f.stsStatus != 0 {
			w.WriteHeader(f.stsStatus)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"The audience in ID Token does not match"}`))
			return
		}
		w.Write([]byte(`{"access_token":"federated","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/projects/-/serviceAccounts/", func(w http.ResponseWriter, r *http.Request) {
		f.impersonAs = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/-/serviceAccounts/"), ":generateAccessToken")
		f.bearer = r.Header.Get("Authorization")
		w.Write([]byte(`{"accessToken":"impersonated","expireTime":"2026-10-17T12:30:00Z"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return endpoints{sts: srv.URL + "/v1/token", iamCredentials: srv.URL + "/v1", client: srv.Client()}
}

func TestDirectAccess(t *testing.T) {
	f := &fakeGoogle{}
	resp, err := handle(baseRequest(t), f.server(t), fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Auth["europe-west4-docker.pkg.dev"]
	if got.Username != "oauth2accesstoken" || got.Password != "federated" {
		t.Fatalf("auth = %+v", got)
	}
	if resp.CacheDuration != "55m0s" || resp.CacheKeyType != "Registry" {
		t.Fatalf("cache = %s/%s", resp.CacheKeyType, resp.CacheDuration)
	}
	if a := f.stsForm["audience"]; len(a) != 1 || a[0] != aud {
		t.Fatalf("sts audience = %v", a)
	}
	if f.stsForm["subject_token_type"][0] != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("subject_token_type = %v", f.stsForm["subject_token_type"])
	}
	if f.impersonAs != "" {
		t.Fatal("impersonated without the annotation")
	}
}

func TestImpersonation(t *testing.T) {
	f := &fakeGoogle{}
	req := baseRequest(t)
	req.ServiceAccountAnnotations[AnnotationServiceAccount] = "puller@proj.iam.gserviceaccount.com"
	resp, err := handle(req, f.server(t), fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if f.impersonAs != "puller@proj.iam.gserviceaccount.com" || f.bearer != "Bearer federated" {
		t.Fatalf("impersonation call = %q with %q", f.impersonAs, f.bearer)
	}
	if resp.Auth["europe-west4-docker.pkg.dev"].Password != "impersonated" {
		t.Fatal("did not return the impersonated token")
	}
	// expireTime 30m out, minus the 5m margin.
	if resp.CacheDuration != "25m0s" {
		t.Fatalf("cacheDuration = %s", resp.CacheDuration)
	}
}

func TestProviderAnnotationMayCarryPrefix(t *testing.T) {
	req := baseRequest(t)
	req.ServiceAccountAnnotations[AnnotationProvider] = aud
	if _, err := handle(req, (&fakeGoogle{}).server(t), fixedNow); err != nil {
		t.Fatal(err)
	}
}

func TestAudienceAsStringAndHTTPSForm(t *testing.T) {
	for _, a := range []any{aud, "https:" + aud} {
		req := baseRequest(t)
		req.ServiceAccountToken = jwt(t, a)
		if _, err := handle(req, (&fakeGoogle{}).server(t), fixedNow); err != nil {
			t.Fatalf("aud %v: %v", a, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*request)
		want   string
	}{
		"v1beta1":        {func(r *request) { r.APIVersion = "credentialprovider.kubelet.k8s.io/v1beta1" }, "v1-only"},
		"no token":       {func(r *request) { r.ServiceAccountToken = "" }, "tokenAttributes"},
		"no annotation":  {func(r *request) { delete(r.ServiceAccountAnnotations, AnnotationProvider) }, "requiredServiceAccountAnnotationKeys"},
		"wrong audience": {func(r *request) { r.ServiceAccountToken = jwt(t, "https://kubernetes.default.svc") }, "serviceAccountTokenAudience"},
		"foreign host":   {func(r *request) { r.Image = "ghcr.io/owner/app:v1" }, "narrow matchImages"},
		"no host":        {func(r *request) { r.Image = "busybox:1.37.0" }, "no registry host"},
		"lookalike host": {func(r *request) { r.Image = "evil.pkg.dev.example.com/app:v1" }, "narrow matchImages"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeGoogle{}
			req := baseRequest(t)
			c.mutate(&req)
			_, err := handle(req, f.server(t), fixedNow)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
			if f.stsForm != nil {
				t.Fatal("refused request still reached STS")
			}
		})
	}
}

func TestSTSErrorDoesNotEchoToken(t *testing.T) {
	f := &fakeGoogle{stsStatus: http.StatusBadRequest}
	req := baseRequest(t)
	_, err := handle(req, f.server(t), fixedNow)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), req.ServiceAccountToken) {
		t.Fatal("error message contains the ServiceAccount token")
	}
}

func TestRunRoundTrip(t *testing.T) {
	in, _ := json.Marshal(baseRequest(t))
	var out strings.Builder
	if err := run(strings.NewReader(string(in)), &out, (&fakeGoogle{}).server(t), fixedNow); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["kind"] != "CredentialProviderResponse" || resp["apiVersion"] != apiVersion {
		t.Fatalf("response = %v", resp)
	}
}

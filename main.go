// Command gcp-wif-credential-provider is a kubelet image credential provider
// that pulls from Google Artifact Registry using GCP Workload Identity
// Federation, on clusters that are not GKE.
//
// The kubelet (1.34+, KEP-4412) hands the plugin a ServiceAccount token
// bound to the pod being started. The plugin exchanges it at Google's STS
// for a federated access token, optionally impersonates a GCP service
// account with it, and returns `oauth2accesstoken:<token>` for the
// registry. No key, no Secret, no imagePullSecrets.
//
// It speaks only credentialprovider.kubelet.k8s.io/v1, because that is the
// only version in which the kubelet sends ServiceAccount tokens.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	apiVersion = "credentialprovider.kubelet.k8s.io/v1"

	// AnnotationProvider names the WIF provider, in the same form Flux's
	// gcp.auth.fluxcd.io/workload-identity-provider annotation uses:
	// projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER.
	// List it under requiredServiceAccountAnnotationKeys so a pod opts in
	// through its ServiceAccount and every other pod is left alone.
	AnnotationProvider = "gcp-wif-credential-provider.dlouwers.github.io/workload-identity-provider"

	// AnnotationServiceAccount, when present, is a GCP service account
	// email to impersonate with the federated token. Leave it unset for
	// direct resource access, where IAM is granted to the principal://
	// identity itself. List it under optionalServiceAccountAnnotationKeys.
	AnnotationServiceAccount = "gcp-wif-credential-provider.dlouwers.github.io/service-account"

	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

	// Credentials are returned for these registry hosts only. A GCP access
	// token handed to the kubelet for any other host would be sent to that
	// host, so a too-broad matchImages must fail closed here.
	registrySuffix = ".pkg.dev"

	// The kubelet reuses a response for cacheDuration; stop short of the
	// token's real expiry so a pull never starts with a token about to lapse.
	expiryMargin = 5 * time.Minute
	minCache     = time.Minute
)

type request struct {
	APIVersion                string            `json:"apiVersion"`
	Kind                      string            `json:"kind"`
	Image                     string            `json:"image"`
	ServiceAccountToken       string            `json:"serviceAccountToken"`
	ServiceAccountAnnotations map[string]string `json:"serviceAccountAnnotations"`
}

type authConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type response struct {
	APIVersion    string                `json:"apiVersion"`
	Kind          string                `json:"kind"`
	CacheKeyType  string                `json:"cacheKeyType"`
	CacheDuration string                `json:"cacheDuration,omitempty"`
	Auth          map[string]authConfig `json:"auth"`
}

// endpoints are variables so tests can point them at an httptest server.
type endpoints struct {
	sts            string
	iamCredentials string
	client         *http.Client
}

func defaultEndpoints() endpoints {
	return endpoints{
		sts:            "https://sts.googleapis.com/v1/token",
		iamCredentials: "https://iamcredentials.googleapis.com/v1",
		client:         &http.Client{Timeout: 15 * time.Second},
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout, defaultEndpoints(), time.Now); err != nil {
		fmt.Fprintln(os.Stderr, "gcp-wif-credential-provider:", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer, ep endpoints, now func() time.Time) error {
	var req request
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	resp, err := handle(req, ep, now)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(resp)
}

func handle(req request, ep endpoints, now func() time.Time) (*response, error) {
	if req.APIVersion != apiVersion {
		return nil, fmt.Errorf("apiVersion %q not supported, want %q (ServiceAccount tokens are v1-only)", req.APIVersion, apiVersion)
	}
	host, err := registryHost(req.Image)
	if err != nil {
		return nil, err
	}
	if req.ServiceAccountToken == "" {
		return nil, errors.New("no serviceAccountToken in request: set tokenAttributes in the CredentialProviderConfig")
	}
	provider := strings.TrimPrefix(req.ServiceAccountAnnotations[AnnotationProvider], "//iam.googleapis.com/")
	if provider == "" {
		return nil, fmt.Errorf("ServiceAccount has no %s annotation: list it under requiredServiceAccountAnnotationKeys", AnnotationProvider)
	}
	audience := "//iam.googleapis.com/" + provider
	if err := checkAudience(req.ServiceAccountToken, audience); err != nil {
		return nil, err
	}

	token, expiry, err := exchange(ep, audience, req.ServiceAccountToken, now)
	if err != nil {
		return nil, err
	}
	if sa := req.ServiceAccountAnnotations[AnnotationServiceAccount]; sa != "" {
		token, expiry, err = impersonate(ep, sa, token)
		if err != nil {
			return nil, err
		}
	}

	cache := expiry.Sub(now()) - expiryMargin
	if cache < minCache {
		cache = minCache
	}
	return &response{
		APIVersion:    apiVersion,
		Kind:          "CredentialProviderResponse",
		CacheKeyType:  "Registry",
		CacheDuration: cache.Round(time.Second).String(),
		Auth:          map[string]authConfig{host: {Username: "oauth2accesstoken", Password: token}},
	}, nil
}

func registryHost(image string) (string, error) {
	host, _, ok := strings.Cut(image, "/")
	if !ok || !strings.ContainsAny(host, ".:") {
		return "", fmt.Errorf("image %q has no registry host", image)
	}
	if !strings.HasSuffix(host, registrySuffix) {
		return "", fmt.Errorf("refusing to return GCP credentials for %q: only *%s hosts are served, narrow matchImages", host, registrySuffix)
	}
	return host, nil
}

// checkAudience reads, without verifying, the token's aud claim. STS would
// reject a mismatch anyway, but with an error that does not name the
// kubelet's serviceAccountTokenAudience as the thing to fix.
func checkAudience(jwt, want string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("serviceAccountToken is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("serviceAccountToken payload: %w", err)
	}
	var claims struct {
		Aud audiences `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("serviceAccountToken claims: %w", err)
	}
	for _, a := range claims.Aud {
		if a == want || a == "https:"+want {
			return nil
		}
	}
	return fmt.Errorf("serviceAccountToken audience %v does not match the annotated provider %q: set tokenAttributes.serviceAccountTokenAudience to it", []string(claims.Aud), want)
}

// audiences accepts aud as either a string or an array, as RFC 7519 allows.
type audiences []string

func (a *audiences) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audiences{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func exchange(ep endpoints, audience, subjectToken string, now func() time.Time) (string, time.Time, error) {
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {audience},
		"scope":                {cloudPlatformScope},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":        {subjectToken},
	}
	httpReq, err := http.NewRequest(http.MethodPost, ep.sts, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := do(ep.client, httpReq, "sts token exchange", &body); err != nil {
		return "", time.Time{}, err
	}
	if body.AccessToken == "" {
		return "", time.Time{}, errors.New("sts token exchange: empty access_token")
	}
	return body.AccessToken, now().Add(time.Duration(body.ExpiresIn) * time.Second), nil
}

func impersonate(ep endpoints, serviceAccount, federated string) (string, time.Time, error) {
	payload, _ := json.Marshal(map[string]any{"scope": []string{cloudPlatformScope}})
	u := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:generateAccessToken", ep.iamCredentials, url.PathEscape(serviceAccount))
	httpReq, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return "", time.Time{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+federated)
	var body struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if err := do(ep.client, httpReq, "impersonate "+serviceAccount, &body); err != nil {
		return "", time.Time{}, err
	}
	if body.AccessToken == "" {
		return "", time.Time{}, errors.New("impersonate: empty accessToken")
	}
	return body.AccessToken, body.ExpireTime, nil
}

// do sends req and decodes a 2xx JSON body into v. On failure it reports the
// status and Google's error body, which describes the problem without
// echoing the token that was sent.
func do(c *http.Client, req *http.Request, what string, v any) error {
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%s: read body: %w", what, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d: %s", what, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: decode: %w", what, err)
	}
	return nil
}

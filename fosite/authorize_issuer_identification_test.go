// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/hydra/v2/fosite"
)

// The trailing slash is part of the issuer identifier: a client compares the
// parameter with the discovery document's issuer as a plain string.
const testIssuer = "https://issuer.example.com/"

func issuerTestRequest(t *testing.T, mode ResponseModeType) *AuthorizeRequest {
	t.Helper()
	redirectURI, err := url.Parse("https://client.example.com/callback?tenant=a")
	require.NoError(t, err)
	ar := NewAuthorizeRequest()
	ar.RedirectURI = redirectURI
	ar.ResponseMode = mode
	ar.State = "the-state"
	ar.Client = &DefaultClient{RedirectURIs: []string{redirectURI.String()}}
	return ar
}

// responseParameters returns what the client receives, wherever the response
// mode put it.
func responseParameters(t *testing.T, mode ResponseModeType, rw *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if mode == ResponseModeFormPost {
		body := rw.Body.String()
		values := url.Values{}
		for _, name := range []string{"iss", "code", "state", "error"} {
			marker := `name="` + name + `" value="`
			if _, rest, found := strings.Cut(body, marker); found {
				value, _, _ := strings.Cut(rest, `"`)
				values.Set(name, value)
			}
		}
		return values
	}
	location, err := url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	if mode == ResponseModeFragment {
		values, err := url.ParseQuery(location.Fragment)
		require.NoError(t, err)
		return values
	}
	return location.Query()
}

func TestAuthorizeResponsesIdentifyTheIssuer(t *testing.T) {
	for _, mode := range []ResponseModeType{ResponseModeDefault, ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost} {
		t.Run("mode="+string(mode), func(t *testing.T) {
			provider := &Fosite{Config: &Config{IDTokenIssuer: testIssuer}}

			t.Run("success", func(t *testing.T) {
				resp := NewAuthorizeResponse()
				resp.AddParameter("code", "the-code")
				resp.AddParameter("state", "the-state")
				rw := httptest.NewRecorder()
				provider.WriteAuthorizeResponse(context.Background(), rw, issuerTestRequest(t, mode), resp)

				parameters := responseParameters(t, mode, rw)
				assert.Equal(t, []string{testIssuer}, parameters["iss"])
				assert.Equal(t, "the-code", parameters.Get("code"))
				assert.Equal(t, "the-state", parameters.Get("state"))
			})

			t.Run("error", func(t *testing.T) {
				rw := httptest.NewRecorder()
				provider.WriteAuthorizeError(context.Background(), rw, issuerTestRequest(t, mode), ErrAccessDenied)

				parameters := responseParameters(t, mode, rw)
				assert.Equal(t, []string{testIssuer}, parameters["iss"])
				assert.Equal(t, "access_denied", parameters.Get("error"))
				assert.Equal(t, "the-state", parameters.Get("state"))
			})
		})
	}
}

func TestAuthorizeResponsesKeepTheRedirectURIsOwnQuery(t *testing.T) {
	provider := &Fosite{Config: &Config{IDTokenIssuer: testIssuer}}
	resp := NewAuthorizeResponse()
	resp.AddParameter("code", "the-code")
	rw := httptest.NewRecorder()
	provider.WriteAuthorizeResponse(context.Background(), rw, issuerTestRequest(t, ResponseModeQuery), resp)

	assert.Equal(t, http.StatusSeeOther, rw.Code)
	location, err := url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "a", location.Query().Get("tenant"))
	assert.Contains(t, location.RawQuery, "iss="+url.QueryEscape(testIssuer), "the issuer must be form-encoded, slash included")
}

func TestAuthorizeResponsesOmitAnIssuerThatIsNotConfigured(t *testing.T) {
	provider := &Fosite{Config: new(Config)}

	resp := NewAuthorizeResponse()
	resp.AddParameter("code", "the-code")
	rw := httptest.NewRecorder()
	provider.WriteAuthorizeResponse(context.Background(), rw, issuerTestRequest(t, ResponseModeQuery), resp)
	assert.NotContains(t, responseParameters(t, ResponseModeQuery, rw), "iss")

	rw = httptest.NewRecorder()
	provider.WriteAuthorizeError(context.Background(), rw, issuerTestRequest(t, ResponseModeQuery), ErrAccessDenied)
	assert.NotContains(t, responseParameters(t, ResponseModeQuery, rw), "iss")
}

func TestAnErrorThatCannotBeRedirectedCarriesNoIssuer(t *testing.T) {
	// Without a usable redirect URI the error is shown to the user, not sent
	// to a client, so there is no authorization response to identify.
	provider := &Fosite{Config: &Config{IDTokenIssuer: testIssuer}}
	ar := NewAuthorizeRequest()
	ar.Client = &DefaultClient{}
	rw := httptest.NewRecorder()
	provider.WriteAuthorizeError(context.Background(), rw, ar, ErrInvalidRequest)

	assert.Empty(t, rw.Header().Get("Location"))
	assert.NotContains(t, rw.Body.String(), testIssuer)
}

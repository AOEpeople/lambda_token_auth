package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	auth "token_authorizer"
)

type TestCase struct {
	Claims  string
	Rules   string
	IsMatch bool
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func TestTokenValidator_RetrieveClaimsFromToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "key-id",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	jwkSet := JWKSet{
		Keys: []JWK{jwk},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":             "https://issuer.example.com",
		"sub":             "1234567890",
		"aud":             []string{"tolen_validation_test"},
		"exp":             time.Now().Add(time.Hour).Unix(),
		"nbf":             time.Now().Unix(),
		"iat":             time.Now().Unix(),
		"jti":             "abcdef123456",
		"namespace_id":    "12343323",
		"namespace_path":  "AOEpeople",
		"project_id":      "3433",
		"project_path":    "AOEpeople/lambda_token_auth",
		"user_id":         "999683",
		"pipeline_id":     "999683",
		"pipeline_source": "push",
		"job_id":          "232558",
		"ref":             "main",
		"ref_type":        "branch",
		"ref_protected":   "true",
	})
	token.Header["kid"] = jwk.Kid
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Errorf("Error signing token: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(jwkSet)
			if err != nil {
				t.Errorf("Error encoding jwks: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("Not found"))
			if err != nil {
				t.Errorf("Error writing response jwks: %v", err)
			}
		}
	}))
	defer server.Close()

	tokenValidator := auth.NewTokenValidator(fmt.Sprintf("%s/jwks", server.URL))
	claims, err := tokenValidator.RetrieveClaimsFromToken(context.TODO(), signedToken)
	if err != nil {
		t.Errorf("Function returned an error: %v", err)
	}

	claimsResult := jwt.MapClaims{}
	err = json.Unmarshal(claims.ClaimsJSON, &claimsResult)
	if err != nil {
		t.Errorf("Function returned an error: %v", err)
	}

	if claimsResult["project_path"] != "AOEpeople/lambda_token_auth" {
		t.Errorf("Unexpected project_path %s", claimsResult["project_path"])
	}
}

func TestTokenValidator_MatchClaimsInternal(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		tests := map[string]TestCase{
			"01_simple_match": {
				Claims:  "{\"foo\": \"bar\"}",
				Rules:   "{\"foo\": \"bar\"}",
				IsMatch: true,
			},
			"02_simple_mismatch": {
				Claims:  "{\"foo\": \"bar\"}",
				Rules:   "{\"foo\": \"foo\"}",
				IsMatch: false,
			},
			"03_complex_match": {
				Claims:  "{\"namespace_id\": \"172\",\"namespace_path\": \"niklas.fassbender\",\"project_id\": \"1093\",\"project_path\": \"niklas.fassbender/runner-trial\",\"user_id\": \"134\",\"user_login\": \"niklas.fassbender\",\"user_email\": \"niklas.fassbender@aoe.com\",\"pipeline_id\": \"1255137\",\"job_id\": \"2769626\",\"ref\": \"master\",\"ref_type\": \"branch\",\"ref_protected\": \"true\",\"jti\": \"439b39a2-0d31-4ab6-aae7-e73805a12dce\",\"iss\": \"gitlab.aoe.com\",\"iat\": 1619003306,\"nbf\": 1619003301,\"exp\": 1619006906,\"sub\": \"job_2769626\"\n}",
				Rules:   "{\"namespace_id\": \"172\"}",
				IsMatch: true,
			},
			"03_nested_match": {
				Claims:  "{\"foo\": {\"bar\": \"botz\"}, \"bum\": \"bang\"}",
				Rules:   "{\"foo\": {\"bar\": \"botz\"}}",
				IsMatch: true,
			},
			"04_nested_mistmatch": {
				Claims:  "{\"foo\": {\"bar\": \"botz\"}, \"bum\": \"bang\"}",
				Rules:   "{\"foo\": true}",
				IsMatch: false,
			},
			"05_deeply_nested_mistmatch": {
				Claims:  "{\"foo\": {\"bar\": {\"bar\": \"botz\"}}, \"bum\": \"bang\"}",
				Rules:   "{\"foo\": {\"bar\": \"botz\"}}",
				IsMatch: false,
			},
		}
		ctx := context.TODO()
		for name, testCase := range tests {
			t.Run(name, func(t *testing.T) {
				matches, err := auth.MatchClaimsInternal(ctx, []byte(testCase.Claims), []byte(testCase.Rules))
				assert.Equal(t, err, nil)
				assert.Equal(t, testCase.IsMatch, matches)
			})
		}
	})

	t.Run("error handling", func(t *testing.T) {
		tests := map[string]TestCase{
			"01_empty": {
				Claims: "",
				Rules:  "",
			},
			"02_array_handling": {
				Claims: "{\"roles\": [\"key\": \"value\"]}",
				Rules:  "{\"roles\": [\"key\": \"value\"]}",
			},
			"03_nested_error_handling": {
				Claims: "{\"roles\": {\"sub\": [\"key\": \"value\"]}",
				Rules:  "{\"roles\": {\"sub\": [\"key\": \"value\"]}",
			},
			"04_null": {
				Claims: "{\"namespace_id\": \"172\", \"roles\": null}",
				Rules:  "{\"namespace_id\": \"172\", \"roles\": null}",
			},
		}
		ctx := context.TODO()
		for name, testCase := range tests {
			t.Run(name, func(t *testing.T) {
				matches, err := auth.MatchClaimsInternal(ctx, []byte(testCase.Claims), []byte(testCase.Rules))
				assert.Error(t, err)
				assert.Equal(t, false, matches)
			})
		}
	})
}

func TestTokenValidator_MatchClaims(t *testing.T) {
	ctx := context.TODO()

	claimJson := []byte("{\"namespace_id\": \"172\"}")
	claims := &auth.Claims{ClaimsJSON: claimJson}

	t.Run("match", func(t *testing.T) {
		tokenValidator := auth.TokenValidator{}
		result := tokenValidator.MatchClaims(ctx, claims, claimJson)
		assert.Equal(t, true, result)
	})

	t.Run("mismatch", func(t *testing.T) {
		tokenValidator := auth.TokenValidator{}
		result := tokenValidator.MatchClaims(ctx, claims, []byte("{\"namespace_id\": \"12\"}"))
		assert.Equal(t, false, result)
	})
	t.Run("unsupported json", func(t *testing.T) {

		claimJson := []byte("{\"namespace_id\": []]}")
		claims := &auth.Claims{ClaimsJSON: claimJson}

		tokenValidator := auth.TokenValidator{}
		result := tokenValidator.MatchClaims(ctx, claims, claimJson)
		assert.Equal(t, false, result)
	})
}

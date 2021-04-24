package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	auth "token_authorizer"
)

type TestCase struct {
	Claims  string
	Rules   string
	IsMatch bool
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

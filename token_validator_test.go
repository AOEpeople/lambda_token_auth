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

func TestMatchClaimsInternal(t *testing.T) {
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
}

func TestMatchClaimsInternalErrorHandling(t *testing.T) {
	tests := map[string]TestCase{
		"01_empty": {
			Claims:  "",
			Rules:   "",
			IsMatch: false,
		},
		"02_array_handling": {
			Claims:  "{\"roles\": [\"key\": \"value\"]}",
			Rules:   "{\"roles\": [\"key\": \"value\"]}",
			IsMatch: false,
		},
		"03_nested_error_handling": {
			Claims:  "{\"roles\": {\"sub\": [\"key\": \"value\"]}",
			Rules:   "{\"roles\": {\"sub\": [\"key\": \"value\"]}",
			IsMatch: false,
		},
		"04_null": {
			Claims:  "{\"namespace_id\": \"172\", \"roles\": null}",
			Rules:   "{\"namespace_id\": \"172\", \"roles\": null}",
			IsMatch: false,
		},
	}
	ctx := context.TODO()
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			matches, err := auth.MatchClaimsInternal(ctx, []byte(testCase.Claims), []byte(testCase.Rules))
			assert.NotEqual(t, err, nil)
			assert.Equal(t, testCase.IsMatch, matches)
		})
	}
}
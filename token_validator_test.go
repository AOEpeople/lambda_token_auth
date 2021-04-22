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

//TODO testing for errors
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
			Claims:  "{\n    \"namespace_id\": \"172\",\n    \"namespace_path\": \"niklas.fassbender\",\n    \"project_id\": \"1093\",\n    \"project_path\": \"niklas.fassbender/runner-trial\",\n    \"user_id\": \"134\",\n    \"user_login\": \"niklas.fassbender\",\n    \"user_email\": \"niklas.fassbender@aoe.com\",\n    \"pipeline_id\": \"1255137\",\n    \"job_id\": \"2769626\",\n    \"ref\": \"master\",\n    \"ref_type\": \"branch\",\n    \"ref_protected\": \"true\",\n    \"jti\": \"439b39a2-0d31-4ab6-aae7-e73805a12dce\",\n    \"iss\": \"gitlab.aoe.com\",\n    \"iat\": 1619003306,\n    \"nbf\": 1619003301,\n    \"exp\": 1619006906,\n    \"sub\": \"job_2769626\"\n}",
			Rules:   "{\"namespace_id\": \"172\"}",
			IsMatch: true,
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

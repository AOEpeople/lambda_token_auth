package auth_test

import (
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
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			matches, err := auth.MatchClaimsInternal([]byte(testCase.Claims), []byte(testCase.Rules))
			assert.Equal(t, err, nil)
			assert.Equal(t, testCase.IsMatch, matches)
		})
	}
}

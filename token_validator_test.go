package token_authorizer_test

import (
	main "token_authorizer"
	"reflect"
	"testing"
)

func TestMatchRuleToClaims(t *testing.T) {

	tests := []struct {
		input *main.GitlabClaims
		want  bool
	}{
		{input: &main.GitlabClaims{NamespaceId: "1"}, want: false},
		{input: &main.GitlabClaims{NamespaceId: "2"}, want: true},
		{input: &main.GitlabClaims{NamespaceId: "2", ProjectId: "5"}, want: true},
		{input: &main.GitlabClaims{NamespaceId: "2", ProjectId: "4"}, want: false},
	}
	tokenClaims := &main.GitlabClaims{
		NamespaceId: "2",
		NamespacePath: "/path/to/repo",
		ProjectId: "5",
		ProjectPath: "/bla/blub",
	}
	tokenValidator := main.TokenValidator{}
	for i, tc := range tests {
		got := tokenValidator.MatchClaims(tokenClaims, tc.input)
		if !reflect.DeepEqual(tc.want, got) {
			t.Errorf("TestMatchRuleToClaims %d: expected got %v; want %v - input: %v", i, got, tc.want, tc.input)
		}
	}
}


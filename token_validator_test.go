package token_authorizer_test

import (
	"reflect"
	"testing"
	main "token_authorizer"
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
			t.Errorf("TestMatchRuleToClaims %d: expected got %v; want %v - inputClaims: %v", i, got, tc.want, tc.input)
		}
	}
}

func TestValidateClaimsForRule(t *testing.T) {
	tests := []struct {
		inputRole string
		inputNamespaceId string
		wantRule    int
		wantErr     bool
	}{
		{inputRole: "one", inputNamespaceId: "1",  wantRule: 0, wantErr: false},
		{inputRole: "two", inputNamespaceId: "1", wantRule: 0, wantErr: true},
		{inputRole: "three", inputNamespaceId: "1", wantRule: 0, wantErr: true},
		{inputRole: "two", inputNamespaceId: "2", wantRule: 1, wantErr: false},
		{inputRole: "two", inputNamespaceId: "1", wantRule: 0, wantErr: true},
	}

	var rules []main.Rule
	rules = append(rules,main.Rule{
		Role: "one",
		ClaimValues: main.GitlabClaims{NamespaceId: "1"},
	})
	rules = append(rules,main.Rule{
		Role: "two",
		ClaimValues: main.GitlabClaims{NamespaceId: "2"},
	})
	tokenValidator := main.TokenValidator{}
	for i, tc := range tests {
		tokenClaims := &main.GitlabClaims{NamespaceId: tc.inputNamespaceId}
		rule, err := tokenValidator.ValidateClaimsForRule(tokenClaims, tc.inputRole, rules)
		if tc.wantErr && err == nil {
			t.Errorf("TestValidateClaimsForRule %d: Expected empty rule within the result but got %s", i, rule.Role)
		} else if !tc.wantErr && rule == nil {
			t.Errorf("TestValidateClaimsForRule %d Expected rule %s but did not get it",i, tc.inputRole)
		} else if !tc.wantErr && rules[tc.wantRule].Role != rule.Role {
			t.Errorf("TestValidateClaimsForRule %d: Expected %s get %s", i, rules[tc.wantRule].Role, rule.Role)
		}
	}
}

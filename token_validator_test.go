package token_authorizer_test

import (
	"reflect"
	"testing"
	main "token_authorizer"
)

func TestMatchRuleToClaims(t *testing.T) {
	tests := map[string]struct {
		input *main.GitlabClaims
		want  bool
	}{
		"simple_match": {input: &main.GitlabClaims{NamespaceId: "1"}, want: false},
		"simple_mismatch": {input: &main.GitlabClaims{NamespaceId: "2"}, want: true},
		"double_match": {input: &main.GitlabClaims{NamespaceId: "2", ProjectId: "5"}, want: true},
		"double_mismatch": {input: &main.GitlabClaims{NamespaceId: "2", ProjectId: "4"}, want: false},
	}
	tokenClaims := &main.GitlabClaims{
		NamespaceId: "2",
		NamespacePath: "/path/to/repo",
		ProjectId: "5",
		ProjectPath: "/bla/blub",
	}
	tokenValidator := main.TokenValidator{}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tokenValidator.MatchClaims(tokenClaims, tc.input)
			if !reflect.DeepEqual(tc.want, got) {
				t.Errorf("expected got %v; want %v - inputClaims: %v", got, tc.want, tc.input)
			}
		})
	}
}

func TestValidateClaimsForRule(t *testing.T) {
	tests := map[string]struct {
		inputRole string
		inputNamespaceId string
		wantRule    int
		wantErr     bool
	}{
		"valid_check_one": {inputRole: "one", inputNamespaceId: "1",  wantRule: 0, wantErr: false},
		"valid_check_two": {inputRole: "two", inputNamespaceId: "2", wantRule: 1, wantErr: false},
		"claim_mismatch_one": {inputRole: "one", inputNamespaceId: "2", wantErr: true},
		"claim_mismatch_two": {inputRole: "two", inputNamespaceId: "1", wantErr: true},
		"role_missing": {inputRole: "three", inputNamespaceId: "1", wantErr: true},

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
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tokenClaims := &main.GitlabClaims{NamespaceId: tc.inputNamespaceId}
			rule, err := tokenValidator.ValidateClaimsForRule(tokenClaims, tc.inputRole, rules)
			if tc.wantErr && err == nil {
				t.Errorf("expected empty rule within the result but got %s", rule.Role)
			} else if !tc.wantErr && rule == nil {
				t.Errorf("expected rule %s but did not get it", tc.inputRole)
			} else if !tc.wantErr && rules[tc.wantRule].Role != rule.Role {
				t.Errorf("expected %s get %s", rules[tc.wantRule].Role, rule.Role)
			}
		})
	}
}

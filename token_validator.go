package auth

import (
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/dgrijalva/jwt-go"
	"log"
	"reflect"
	"strings"
)

// TokenValidatorInterface interface of validation objects
type TokenValidatorInterface interface {
	RetrieveClaimsFromToken(tokenInput string) (*GitlabClaims, error)
	MatchClaims(tokenClaims *GitlabClaims, ruleClaims *GitlabClaims) bool
	ValidateClaimsForRule(tokenClaims *GitlabClaims, requestedRole string, rules []Rule) (*Rule, error)
}

// NewTokenValidator creates a new TokenValidator for a given system
func NewTokenValidator(jwksURL string) *TokenValidator {
	jwks, err := keyfunc.Get(jwksURL)
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %v", err)
	}

	validator := &TokenValidator{
		jwks: jwks,
	}
	return validator
}

// TokenValidator implements a TokenValidatorInterface validating jwt tokens with a remote server
type TokenValidator struct {
	jwks *keyfunc.JWKS
}

// RetrieveClaimsFromToken validate the token and get all included claims
func (t *TokenValidator) RetrieveClaimsFromToken(tokenInput string) (*GitlabClaims, error) {
	token, err := jwt.ParseWithClaims(tokenInput, &GitlabClaims{}, t.jwks.KeyFunc)
	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, fmt.Errorf("that's not even a token")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return nil, fmt.Errorf("timing is everything - token is either expired or not active yet")
			} else {
				return nil, fmt.Errorf("couldn't handle this token: %w", err)
			}
		} else {
			return nil, fmt.Errorf("couldn't handle this token: %w", err)
		}
	}

	claims, ok := token.Claims.(*GitlabClaims)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve claims from token: %w", err)
	}
	log.Printf("%v %v", claims.ProjectID, claims.StandardClaims.ExpiresAt)
	return claims, nil
}

// MatchClaims check if all claims from a token are presented within rules
func (t *TokenValidator) MatchClaims(tokenClaims *GitlabClaims, ruleClaims *GitlabClaims) bool {
	match := true
	ruleClaimsRefection := reflect.ValueOf(ruleClaims).Elem()
	tokenClaimsRefection := reflect.ValueOf(tokenClaims).Elem()
	for i := 0; i < ruleClaimsRefection.NumField(); i++ {
		ruleClaimsFieldValue := reflect.Value(ruleClaimsRefection.Field(i)).String()
		tokenClaimsFieldValue := reflect.Value(tokenClaimsRefection.Field(i)).String()
		if ruleClaimsFieldValue != "" && strings.Compare(ruleClaimsFieldValue,tokenClaimsFieldValue) != 0 {
			match = false
			break
		}
	}
	return match
}

// ValidateClaimsForRule check if
func (t *TokenValidator) ValidateClaimsForRule(tokenClaims *GitlabClaims, requestedRole string, rules []Rule) (*Rule, error) {
	for _, rule := range rules {
		if strings.Compare(rule.Role, requestedRole) == 0 && t.MatchClaims(tokenClaims, &rule.ClaimValues) {
			return &rule, nil
		}
	}
	return nil, fmt.Errorf("unable to find matching rule")
}

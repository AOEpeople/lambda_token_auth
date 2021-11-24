package auth

import (
	"bytes"
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/buger/jsonparser"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	"strings"
)

// TokenValidatorInterface interface of validation objects
type TokenValidatorInterface interface {
	RetrieveClaimsFromToken(ctx context.Context, tokenInput string) (*Claims, error)
	MatchClaims(ctx context.Context, tokenClaims *Claims, ruleClaims []byte) bool
	ValidateClaimsForRule(ctx context.Context, tokenClaims *Claims, requestedRole string, rules []Rule) (*Rule, error)
}

// NewTokenValidator creates a new TokenValidator for a given system
func NewTokenValidator(jwksURL string) *TokenValidator {
	log.Debugf("Using %s for JWK retrival", jwksURL)
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
	jwks *keyfunc.JWKs
}

// RetrieveClaimsFromToken validate the token and get all included claims
func (t *TokenValidator) RetrieveClaimsFromToken(ctx context.Context, tokenInput string) (*Claims, error) {

	token, err := jwt.ParseWithClaims(tokenInput, &jwt.StandardClaims{}, t.jwks.Keyfunc)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}

	Logger(ctx).Debugf("Raw token: %s", token.Raw)

	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("error splitting token into parts")
	}

	claimsJSON, err := jwt.DecodeSegment(parts[1])

	if err != nil {
		return nil, fmt.Errorf("error decoding claims section: %s", err)
	}

	claims := &Claims{
		ClaimsJSON:     claimsJSON,
		RegisteredClaims: token.Claims.(*jwt.RegisteredClaims),
	}

	return claims, nil
}

// MatchClaimsInternal implements claims matching on the json byte data level
func MatchClaimsInternal(ctx context.Context, claims []byte, rules []byte) (bool, error) {
	matches := true

	err := jsonparser.ObjectEach(rules, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		keyString := string(key)

		claimsObj, claimsObjDataType, _, err := jsonparser.Get(claims, keyString)
		//Check for parsing errors
		if err != nil && claimsObjDataType != jsonparser.NotExist {
			return err
		}
		//Check if rule type matches with claim type
		if claimsObjDataType != dataType {
			matches = false
			return nil
		}

		switch dataType {
		case jsonparser.Object:
			//Check if object matches with rules
			objMatches, err := MatchClaimsInternal(ctx, claimsObj, value)
			if err != nil {
				return err
			}
			//Check if object matches
			if !objMatches {
				matches = false
				return nil
			}
		case jsonparser.String, jsonparser.Boolean, jsonparser.Number:
			if !bytes.Equal(claimsObj, value) {
				matches = false
				return nil
			}
		case jsonparser.Array:
			return fmt.Errorf("handling for arraytypes not implemented yet")
		case jsonparser.NotExist, jsonparser.Unknown, jsonparser.Null:
			return fmt.Errorf("iterated over a key with type %s. This should not happen", dataType.String())
		}

		return nil
	})
	return matches && err == nil, err
}

// MatchClaims check if all claims from a token are presented within rules
func (t *TokenValidator) MatchClaims(ctx context.Context, tokenClaims *Claims, ruleClaims []byte) bool {
	Logger(ctx).Debugf("Rules JSON: %s", ruleClaims)
	match, err := MatchClaimsInternal(ctx, tokenClaims.ClaimsJSON, ruleClaims)
	if err != nil {
		Logger(ctx).Warnf("error matching claims: %s", err)
	}
	return match && err == nil
}

// ValidateClaimsForRule check if
func (t *TokenValidator) ValidateClaimsForRule(ctx context.Context, tokenClaims *Claims, requestedRole string, rules []Rule) (*Rule, error) {
	for _, rule := range rules {
		if strings.Compare(rule.Role, requestedRole) == 0 && t.MatchClaims(ctx, tokenClaims, rule.ClaimValues) {
			return &rule, nil
		}
	}
	return nil, nil
}

package auth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang-jwt/jwt/v4"
	auth "token_authorizer"
	"token_authorizer/mock"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationHandler(t *testing.T) {
	ctx := context.Background()

	t.Run("args invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		validator := mock.NewMockTokenValidatorInterface(ctrl)
		consumer := mock.NewMockAwsConsumerInterface(ctrl)
		handler := auth.NewHandler(consumer, validator)
		response, err := handler(ctx, auth.Event{})
		assert.NoError(t, err)
		assert.Equal(t, "invalid arguments", response.Body)
		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	})

	t.Run("args valid - global rules", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var rules []auth.Rule
		rules = append(rules, auth.Rule{
			Role:        "one",
			ClaimValues: []byte("{\"namespace_id\": \"1\"}"),
		})

		rules = append(rules, auth.Rule{
			Role:        "two",
			ClaimValues: []byte("{\"namespace_id\": \"2\"}"),
		})

		claims := auth.Claims{ClaimsJSON: rules[0].ClaimValues,
			RegisteredClaims: &jwt.RegisteredClaims{
				Subject: "hans",
			}}

		validator := mock.NewMockTokenValidatorInterface(ctrl)
		validator.EXPECT().RetrieveClaimsFromToken(gomock.Any(), gomock.Eq("token")).Return(&claims, nil)
		validator.EXPECT().ValidateClaimsForRule(gomock.Any(), gomock.Eq(&claims), gomock.Eq("one"), gomock.Eq(rules)).Return(&rules[0], nil)

		consumer := mock.NewMockAwsConsumerInterface(ctrl)
		consumer.EXPECT().RetrieveRulesFromRoleTags(gomock.Any(), gomock.Eq("one")).Return(nil, nil)
		consumer.EXPECT().AssumeRole(gomock.Any(), gomock.Eq(&rules[0]), gomock.Eq("hans")).Return(&sts.Credentials{}, nil)
		consumer.EXPECT().Rules().Return(rules)

		handler := auth.NewHandler(consumer, validator)
		event := auth.Event{
			Headers: auth.EventHeaders{Authorization: "token", Accept: "application/json"},
			Query:   auth.EventQuery{Role: "one"},
		}
		response, err := handler(ctx, event)
		assert.NoError(t, err)
		assert.Equal(t, "{\"AccessKeyId\":null,\"Expiration\":null,\"SecretAccessKey\":null,\"SessionToken\":null}", response.Body)
		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("args valid - iam rules", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var globalRules []auth.Rule
		var iamRules []auth.Rule
		iamRules = append(iamRules, auth.Rule{
			Role:        "one",
			ClaimValues: []byte("{\"namespace_id\": \"1\"}"),
		})

		claims := auth.Claims{ClaimsJSON: iamRules[0].ClaimValues,
			RegisteredClaims: &jwt.RegisteredClaims{
				Subject: "hans",
			}}

		validator := mock.NewMockTokenValidatorInterface(ctrl)
		validator.EXPECT().RetrieveClaimsFromToken(gomock.Any(), gomock.Eq("token")).Return(&claims, nil)
		validator.EXPECT().ValidateClaimsForRule(gomock.Any(), gomock.Eq(&claims), gomock.Eq("one"), gomock.Eq(iamRules)).Return(&iamRules[0], nil)

		consumer := mock.NewMockAwsConsumerInterface(ctrl)
		consumer.EXPECT().RetrieveRulesFromRoleTags(gomock.Any(), gomock.Eq("one")).Return(iamRules, nil)
		consumer.EXPECT().AssumeRole(gomock.Any(), gomock.Eq(&iamRules[0]), gomock.Eq("hans")).Return(&sts.Credentials{}, nil)
		consumer.EXPECT().Rules().Return(globalRules)

		handler := auth.NewHandler(consumer, validator)
		event := auth.Event{
			Headers: auth.EventHeaders{Authorization: "token", Accept: "application/json"},
			Query:   auth.EventQuery{Role: "one"},
		}
		response, err := handler(ctx, event)
		assert.NoError(t, err)
		assert.Equal(t, "{\"AccessKeyId\":null,\"Expiration\":null,\"SecretAccessKey\":null,\"SessionToken\":null}", response.Body)
		assert.Equal(t, http.StatusOK, response.StatusCode)
	})
}

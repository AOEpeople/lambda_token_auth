package auth_test

import (
	"context"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/dgrijalva/jwt-go"

	"net/http"

	auth "token_authorizer"
	"token_authorizer/mock"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizationHandler(t *testing.T) {
	ctx := context.Background()

	t.Run("args invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authorizer := mock.NewMockAuthorizer(ctrl)
		handler := auth.NewHandler(authorizer)
		response, err := handler(ctx, auth.Event{})
		assert.NoError(t, err)
		assert.Equal(t, "invalid arguments", response.Body)
		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	})

	t.Run("args valid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var rules []auth.Rule
		rules = append(rules, auth.Rule{
			Role: "one",
			ClaimValues: auth.Claims{
				ClaimsJSON:     []byte("{\"namespace_id\": \"1\""),
				StandardClaims: jwt.StandardClaims{Subject: "hans"},
			},
		})
		rules = append(rules, auth.Rule{
			Role: "two",
			ClaimValues: auth.Claims{
				ClaimsJSON:     []byte("{\"namespace_id\": \"2\""),
				StandardClaims: jwt.StandardClaims{Subject: "hans"},
			},
		})

		tokenValidator := mock.NewMockTokenValidatorInterface(ctrl)
		tokenValidator.EXPECT().RetrieveClaimsFromToken(gomock.Eq("token")).Return(&rules[0].ClaimValues, nil)
		tokenValidator.EXPECT().ValidateClaimsForRule(gomock.Eq(&rules[0].ClaimValues), gomock.Eq("one"), gomock.Eq(rules)).Return(&rules[0], nil)
		awsConsumer := mock.NewMockAwsConsumerInterface(ctrl)
		awsConsumer.EXPECT().ValidateRole(gomock.Eq("one")).Return(true)
		awsConsumer.EXPECT().AssumeRole(gomock.Eq(&rules[0]), gomock.Eq("hans")).Return(&sts.Credentials{}, nil)

		authorizer := mock.NewMockAuthorizer(ctrl)
		authorizer.EXPECT().Config().Return(&auth.Config{
			Rules: rules,
		})
		authorizer.EXPECT().TokenValidator().Return(tokenValidator)
		authorizer.EXPECT().TokenValidator().Return(tokenValidator)
		authorizer.EXPECT().AwsConsumer().Return(awsConsumer)
		authorizer.EXPECT().AwsConsumer().Return(awsConsumer)

		handler := auth.NewHandler(authorizer)
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

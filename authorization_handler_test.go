package token_authorizer_test

import (
	"context"
	"net/http"

	auth "token_authorizer"
	"token_authorizer/mock"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizer(t *testing.T) {
	ctx := context.Background()

	t.Run("args invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		authorizer := mock.NewMockAuthorizationHandler(ctrl)
		handler := auth.NewHandler(authorizer)
		response, err := handler(ctx, auth.HandleEvent{})
		assert.NoError(t, err)
		assert.Equal(t, "Invalid arguments.", response.Body)
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	})
}

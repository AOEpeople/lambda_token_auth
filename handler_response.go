package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/sts"
	"net/http"
)

// HandlerResponse the response format expected by Lambda
// see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
type HandlerResponse struct {
	IsBase64Encoded bool `json:"isBase64Encoded,omitempty"`
	StatusCode      int  `json:"statusCode,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body string `json:"body,omitempty"`
}

// RespondError format a response with an error message
func RespondError(ctx context.Context, err error, statusCode int) (HandlerResponse, error) {
	Logger(ctx).Errorf("error response of request %d, %s", statusCode, err.Error())
	return HandlerResponse{
		StatusCode: statusCode,
		Body: err.Error(),
	}, nil
}

// RespondShellscript format a response as a shellscript
func RespondShellscript(ctx context.Context, credentials *sts.Credentials) (HandlerResponse, error) {
	data := fmt.Sprintf("export AWS_ACCESS_KEY_ID=\"%s\"\n" +
		"export AWS_SECRET_ACCESS_KEY=\"%s\"\n" +
		"export AWS_SESSION_TOKEN=\"%s\"\n",
			*credentials.AccessKeyId,
			*credentials.SecretAccessKey,
			*credentials.SessionToken)
	Logger(ctx).Debug("response successful - responding credentials as script")
	return HandlerResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "text/x-shellscript",
		},
		Body: data,
	}, nil
}

// RespondJSON format a response as json
func RespondJSON(ctx context.Context, credentials *sts.Credentials) (HandlerResponse, error) {
	response, err := json.Marshal(&credentials)
	if err != nil {
		return RespondError(ctx, err, http.StatusInternalServerError)
	}
	Logger(ctx).Debug("response successful - responding credentials as json")
	return HandlerResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: fmt.Sprintf("%s", response),
	}, nil
}
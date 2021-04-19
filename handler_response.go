package lambda_token_auth

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/sts"
	"net/http"
)

// see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
type HandlerResponse struct {
	IsBase64Encoded bool `json:"isBase64Encoded,omitempty"`
	StatusCode      int  `json:"statusCode,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body string `json:"body,omitempty"`
}

func RespondError(err error, statusCode int) (HandlerResponse, error) {
	return HandlerResponse{
		StatusCode: statusCode,
		Body: fmt.Sprintf("%s", err.Error()),
	}, nil
}

func RespondShellscript(credentials *sts.Credentials) (HandlerResponse, error) {
	data := fmt.Sprintf("export AWS_ACCESS_KEY_ID=\"%s\"\n" +
		"export AWS_SECRET_ACCESS_KEY=\"%s\"\n" +
		"export AWS_SESSION_TOKEN=\"%s\"\n",
			*credentials.AccessKeyId,
			*credentials.SecretAccessKey,
			*credentials.SessionToken)
	return HandlerResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "text/x-shellscript",
		},
		Body: data,
	}, nil
}

func RespondJson(credentials *sts.Credentials) (HandlerResponse, error) {
	response, err := json.Marshal(&credentials)
	if err != nil {
		return RespondError(err, http.StatusInternalServerError)
	}

	return HandlerResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: fmt.Sprintf("%s", response),
	}, nil
}
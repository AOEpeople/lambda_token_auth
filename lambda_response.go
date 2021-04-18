package token_authorizer

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/sts"
	"net/http"
)

func RespondError(err error, statusCode int) (HandleResponse, error) {
	return HandleResponse{
		StatusCode: statusCode,
		Body: fmt.Sprintf("%s", err.Error()),
	}, nil
}

func RespondShellscript(credentials *sts.Credentials) (HandleResponse, error) {
	data := fmt.Sprintf("export AWS_ACCESS_KEY_ID=\"%s\"\n" +
		"export AWS_SECRET_ACCESS_KEY=\"%s\"\n" +
		"export AWS_SESSION_TOKEN=\"%s\"\n",
			*credentials.AccessKeyId,
			*credentials.SecretAccessKey,
			*credentials.SessionToken)
	return HandleResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "text/x-shellscript",
		},
		Body: data,
	}, nil
}

func RespondJson(credentials *sts.Credentials) (HandleResponse, error) {
	response, err := json.Marshal(&credentials)
	if err != nil {
		return RespondError(err, http.StatusInternalServerError)
	}

	return HandleResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: fmt.Sprintf("%s", response),
	}, nil
}
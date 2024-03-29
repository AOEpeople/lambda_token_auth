package auth_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"io"
	"strings"
	"testing"
	auth "token_authorizer"
	"token_authorizer/mock"
)

func TestAwsConsumer_ReadConfiguration(t *testing.T) {

	config := &auth.Config{
		Bucket:    "bucket",
		ObjectKey: "key",
	}
	t.Run("happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		r := io.NopCloser(strings.NewReader("{\"jwks_url\": \"https://example.org\"}"))

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetS3Object(gomock.Any(), gomock.Any()).Return(r, nil)

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: config,
		}
		err := consumer.ReadConfiguration()
		assert.NoError(t, err)
		assert.Equal(t, "https://example.org", config.JwksURL)
	})
	t.Run("error handling", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetS3Object(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("mimimi"))

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: config,
		}
		err := consumer.ReadConfiguration()
		assert.Error(t, err)
	})
	t.Run("broken json", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		r := io.NopCloser(strings.NewReader("{\"jwks_url\"}"))

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetS3Object(gomock.Any(), gomock.Any()).Return(r, nil)

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: config,
		}
		err := consumer.ReadConfiguration()
		assert.Error(t, err)
	})
}

func TestAwsConsumer_AssumeRole(t *testing.T) {
	ctx := context.TODO()

	t.Run("happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().AssumeRole(gomock.Eq(&sts.AssumeRoleInput{
			DurationSeconds: aws.Int64(0),
			RoleArn:         aws.String("role:arn"),
			RoleSessionName: aws.String("one"),
		})).Return(&sts.AssumeRoleOutput{
			Credentials: &sts.Credentials{AccessKeyId: aws.String("key")},
		}, nil)

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: &auth.Config{},
		}
		credentials, err := consumer.AssumeRole(ctx, &auth.Rule{
			Role: "role:arn",
		}, "one")
		assert.NoError(t, err)
		assert.Equal(t, "key", *credentials.AccessKeyId)
	})

	t.Run("error handling", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().AssumeRole(gomock.Any()).Return(nil, fmt.Errorf("mimimi"))

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: &auth.Config{},
		}
		credentials, err := consumer.AssumeRole(ctx, &auth.Rule{
			Role: "role:arn",
		}, "one")
		assert.Error(t, err)
		assert.Nil(t, credentials)
	})
}

func TestAwsConsumer_RetrieveRulesFromRoleTags(t *testing.T) {
	ctx := context.TODO()

	t.Run("invalid arn", func(t *testing.T) {
		consumer := auth.AwsConsumer{
			Config: &auth.Config{},
		}
		rules, err := consumer.RetrieveRulesFromRoleTags(ctx, "foooo")
		assert.Error(t, err)
		assert.Nil(t, rules)
	})
	t.Run("happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var tags []*iam.Tag
		tags = append(tags, &iam.Tag{Key: aws.String("token_auth/1"), Value: aws.String(base64.StdEncoding.EncodeToString([]byte("{\"field\":\"valid\"}")))})
		tags = append(tags, &iam.Tag{Key: aws.String("name"), Value: aws.String("assume-me")})

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetRole(gomock.Any()).Return(&iam.GetRoleOutput{
			Role: &iam.Role{
				Tags: tags,
			},
		}, nil)

		consumer := auth.AwsConsumer{
			AWS: serviceWrapper,
			Config: &auth.Config{
				RoleAnnotationsEnabled: true,
				RoleAnnotationPrefix:   "token_auth/1",
			},
		}
		credentials, err := consumer.RetrieveRulesFromRoleTags(ctx, "arn:aws:iam::012345678910:role/assume-me")
		assert.NoError(t, err)
		assert.NotEmpty(t, credentials)
		assert.Equal(t, 1, len(credentials))
		assert.Equal(t, "arn:aws:iam::012345678910:role/assume-me", credentials[0].Role)
	})

	t.Run("disabled role annotations", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var tags []*iam.Tag
		tags = append(tags, &iam.Tag{Key: aws.String("token_auth/1"), Value: aws.String(base64.StdEncoding.EncodeToString([]byte("{\"field\":\"valid\"}")))})
		tags = append(tags, &iam.Tag{Key: aws.String("name"), Value: aws.String("assume-me")})

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetRole(gomock.Any()).Return(&iam.GetRoleOutput{
			Role: &iam.Role{
				Tags: tags,
			},
		}, nil)

		consumer := auth.AwsConsumer{
			AWS: serviceWrapper,
			Config: &auth.Config{
				RoleAnnotationsEnabled: false,
			},
		}
		credentials, err := consumer.RetrieveRulesFromRoleTags(ctx, "arn:aws:iam::012345678910:role/assume-me")
		assert.NoError(t, err)
		assert.Empty(t, credentials)
	})

	t.Run("mismatching role annotations", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var tags []*iam.Tag
		tags = append(tags, &iam.Tag{Key: aws.String("token_auth_prefix/1"), Value: aws.String(base64.StdEncoding.EncodeToString([]byte("{\"field\":\"valid\"}")))})
		tags = append(tags, &iam.Tag{Key: aws.String("name"), Value: aws.String("assume-me")})

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetRole(gomock.Any()).Return(&iam.GetRoleOutput{
			Role: &iam.Role{
				Tags: tags,
			},
		}, nil)

		consumer := auth.AwsConsumer{
			AWS: serviceWrapper,
			Config: &auth.Config{
				RoleAnnotationsEnabled: true,
				RoleAnnotationPrefix:   "token_prefix/",
			},
		}
		credentials, err := consumer.RetrieveRulesFromRoleTags(ctx, "arn:aws:iam::012345678910:role/assume-me")
		assert.NoError(t, err)
		assert.Empty(t, credentials)
	})

	t.Run("missing role", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetRole(gomock.Any()).Return(nil, fmt.Errorf("not found"))

		consumer := auth.AwsConsumer{
			AWS:    serviceWrapper,
			Config: &auth.Config{},
		}
		credentials, err := consumer.RetrieveRulesFromRoleTags(ctx, "arn:aws:iam::012345678910:role/assume-me")
		assert.Error(t, err)
		assert.Empty(t, credentials)
	})

	t.Run("broken tag annotation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var tags []*iam.Tag
		tags = append(tags, &iam.Tag{Key: aws.String("token_auth/1"), Value: aws.String("notbase64")})

		serviceWrapper := mock.NewMockAwsServiceWrapperInterface(ctrl)
		serviceWrapper.EXPECT().GetRole(gomock.Any()).Return(&iam.GetRoleOutput{
			Role: &iam.Role{
				Tags: tags,
			},
		}, nil)

		consumer := auth.AwsConsumer{
			AWS: serviceWrapper,
			Config: &auth.Config{
				RoleAnnotationsEnabled: true,
			},
		}
		credentials, err := consumer.RetrieveRulesFromRoleTags(ctx, "arn:aws:iam::012345678910:role/assume-me")
		assert.NoError(t, err)
		assert.Empty(t, credentials)
	})
}

func TestAwsConsumer_SessionName(t *testing.T) {

	tests := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name:           "truncates long name and replaces invalid characters",
			input:          "abc12345678@#$%^&*()_+-=[]{}|;':\",./<>?defghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
			expectedOutput: "12345678@_+-=,.defghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			name:           "replaces invalid characters but does not truncate short name",
			input:          "valid-name_123",
			expectedOutput: "valid-name_123",
		},
	}
	consumer := auth.AwsConsumer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := consumer.SessionName(tt.input)
			if output != tt.expectedOutput {
				t.Errorf("SessionName(%q) = %q, expected %q", tt.input, output, tt.expectedOutput)
			}
		})
	}
}

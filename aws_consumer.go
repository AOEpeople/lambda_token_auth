package lambda_token_auth

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"regexp"
)

type AwsConsumerInterface interface {
	ReadConfiguration(config *Config, bucket string, key string) error
	AssumeRole(rule *Rule, name string) (*sts.Credentials, error)
	ValidateRole(role string) bool
}

type AwsConsumer struct {
}

func (a *AwsConsumer) ReadConfiguration(config *Config, bucket string, key string) error {
	var err error
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("unable to create a new AWS session: %w", err)
	}
	svc := s3.New(sess, &aws.Config{
		DisableRestProtocolURICleaning: aws.Bool(true),
	})
	resp, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(config); err != nil {
		return fmt.Errorf("Unable to read RULES inputClaims.\n Error: %v", err)
	}
	defer resp.Body.Close()
	return nil
}

func (a *AwsConsumer) AssumeRole(rule *Rule, name string) (*sts.Credentials, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: &rule.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create a new AWS session: %w", err)
	}
	svc := sts.New(sess)
	duration := rule.Duration
	roleToAssumeArn := rule.Role
	sessionName := name
	result, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         &roleToAssumeArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &duration,
	})

	if err != nil {
		return nil, fmt.Errorf("unable to perform sts.AssumeRole: %w", err)
	}
	return result.Credentials, nil
}

func (a *AwsConsumer) ValidateRole(role string) bool {
	validRole := regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[a-zA-Z0-9-_]+$`)
	return validRole.MatchString(role)
}

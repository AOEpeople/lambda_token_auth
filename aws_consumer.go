package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"regexp"
	"strings"
)

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	// ReadConfiguration reads the configured S3 Bucket and returns Config
	ReadConfiguration(config *Config, bucket string, key string) error
	// AssumeRole performs this for the give rule
	AssumeRole(rule *Rule, name string) (*sts.Credentials, error)
	// RetrieveRulesFromRoleTags checks wether a string matches the rule format
	RetrieveRulesFromRoleTags(role string) ([]Rule, error)
}

// AwsConsumer is the implementation of AwsConsumerInterface
type AwsConsumer struct {
}

// ReadConfiguration reads the configured S3 Bucket and returns Config
func (a *AwsConsumer) ReadConfiguration(config *Config, bucket string, key string) error {
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
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(config); err != nil {
		return fmt.Errorf("Unable to read RULES inputClaims.\n Error: %v", err)
	}
	defer resp.Body.Close()
	return nil
}

// AssumeRole performs this for the give rule
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

// RetrieveRulesFromRoleTags checks the IAM role for further rules configured through tags
func (a *AwsConsumer) RetrieveRulesFromRoleTags(role string) ([]Rule, error) {
	validRole := regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[a-zA-Z0-9-_]+$`)
	if !validRole.MatchString(role) {
		return nil, fmt.Errorf("invalid role format")
	}

	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to create a new AWS session: %w", err)
	}
	svc := iam.New(sess)
	result, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: &role,
	})
	var rules []Rule
	for _, tag := range result.Role.Tags {
		if !strings.HasPrefix(*tag.Key,"token_auth/") {
			continue
		}
		ruleDecoded, err := base64.StdEncoding.DecodeString(*tag.Value)
		if err != nil {
			continue
		}
		rule := Rule{}
		err = json.Unmarshal(ruleDecoded, rule)
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

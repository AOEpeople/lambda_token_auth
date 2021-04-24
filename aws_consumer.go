package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/iam"
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
	AWS AwsServiceWrapperInterface
	Config *Config
}

// NewAwsConsumer constructs a new consumer with the proper ServiceWrapper
func NewAwsConsumer(config *Config) *AwsConsumer {
	return &AwsConsumer{
		AWS: &AwsServiceWrapper{},
		Config: config,
	}
}

// ReadConfiguration reads the configured S3 Bucket and returns Config
func (a *AwsConsumer) ReadConfiguration(config *Config, bucket string, key string) error {
	content, err := a.AWS.GetS3Object(bucket, key)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(content)
	if err := decoder.Decode(config); err != nil {
		return fmt.Errorf("Unable to read RULES inputClaims.\n Error: %v", err)
	}
	defer content.Close()
	return nil
}

// AssumeRole performs this for the give rule
func (a *AwsConsumer) AssumeRole(rule *Rule, name string) (*sts.Credentials, error) {
	duration := rule.Duration
	if duration==0 {
		duration = a.Config.Duration
	}
	roleToAssumeArn := rule.Role
	sessionName := name
	result, err := a.AWS.AssumeRole(&sts.AssumeRoleInput{
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
	validRole := regexp.MustCompile(`^arn:AWS:iam::\d{12}:role/[a-zA-Z0-9-_]+$`)
	if !validRole.MatchString(role) {
		return nil, fmt.Errorf("invalid role format")
	}

	result, err := a.AWS.GetRole(&iam.GetRoleInput{
		RoleName: &role,
	})
	if err != nil {
		return nil, err
	}

	if !a.Config.EnableRoleAnnotations {
		return nil, nil
	}

	var rules []Rule
	for _, tag := range result.Role.Tags {
		if !strings.HasPrefix(*tag.Key,"token_auth/") {
			continue
		}
		tagDecoded, err := base64.StdEncoding.DecodeString(*tag.Value)
		if err != nil {
			continue
		}
		rule := Rule{
			Role: role,
			Duration: a.Config.Duration,
			ClaimValues: tagDecoded,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

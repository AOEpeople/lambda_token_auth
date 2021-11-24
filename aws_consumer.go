package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	// ReadConfiguration reads the configured S3 Bucket and refreshes the Config
	ReadConfiguration() error
	// JwksURL returns the configured JWK url
	JwksURL() string
	// Rules holds the globals rules loaded from the S3 bucket
	Rules() []Rule
	// AssumeRole performs this for the give rule
	AssumeRole(ctx context.Context, rule *Rule, name string) (*sts.Credentials, error)
	// RetrieveRulesFromRoleTags checks whether a string matches the rule format
	RetrieveRulesFromRoleTags(ctx context.Context, role string) ([]Rule, error)
}

// AwsConsumer is the implementation of AwsConsumerInterface
type AwsConsumer struct {
	AWS    AwsServiceWrapperInterface
	Config *Config
}

// NewAwsConsumer constructs a new consumer with the proper ServiceWrapper
func NewAwsConsumer(config *Config) (*AwsConsumer, error) {
	consumer := &AwsConsumer{
		AWS:    &AwsServiceWrapper{},
		Config: config,
	}
	if config.Bucket != "" && config.ObjectKey != "" {
		err := consumer.ReadConfiguration()
		if err != nil {
			return nil, err
		}
	}
	return consumer, nil
}

// ReadConfiguration reads the configured S3 Bucket and returns Config
func (a *AwsConsumer) ReadConfiguration() error {
	content, err := a.AWS.GetS3Object(a.Config.Bucket, a.Config.ObjectKey)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(content)
	if err := decoder.Decode(a.Config); err != nil {
		return fmt.Errorf("Unable to read RULES inputClaims.\n Error: %v", err)
	}
	log.Debugf("Successfully imported config %v", a.Config)
	defer content.Close()
	return nil
}

// AssumeRole performs this for the give rule
func (a *AwsConsumer) AssumeRole(ctx context.Context, rule *Rule, name string) (*sts.Credentials, error) {
	duration := rule.Duration
	if duration == 0 {
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
func (a *AwsConsumer) RetrieveRulesFromRoleTags(ctx context.Context, roleArn string) ([]Rule, error) {
	logger := Logger(ctx)

	validRole := regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[a-zA-Z0-9-_]+$`)
	if !validRole.MatchString(roleArn) {
		return nil, fmt.Errorf("invalid role format")
	}

	logger.Debugf("GetRole %s", roleArn[31:])
	result, err := a.AWS.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(roleArn[31:]),
	})
	if err != nil {
		return nil, err
	}

	if !a.Config.RoleAnnotationsEnabled || len(a.Config.RoleAnnotationPrefix) == 0 {
		return nil, nil
	}

	var rules []Rule
	for _, tag := range result.Role.Tags {
		if !strings.HasPrefix(*tag.Key, a.Config.RoleAnnotationPrefix) {
			continue
		}
		tagDecoded, err := base64.StdEncoding.DecodeString(*tag.Value)
		if err != nil {
			continue
		}
		rule := Rule{
			Role:        roleArn,
			Duration:    a.Config.Duration,
			ClaimValues: tagDecoded,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Rules returns the list of claim to role configuration rules
func (a *AwsConsumer) Rules() []Rule {
	return a.Config.Rules
}

// JwksURL forwards the url from the configuration
func (a *AwsConsumer) JwksURL() string {
	return a.Config.JwksURL
}

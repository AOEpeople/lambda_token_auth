package auth

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"io"
)

// AwsServiceWrapperInterface allows to test AWS specific code based on the AWS
type AwsServiceWrapperInterface interface {
	GetS3Object(bucket, key string) (io.ReadCloser, error)
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
}

// AwsServiceWrapper is the implementation of AwsServiceWrapperInterface
// it wraps the actual AWS service call but has no additional functionality implemented
type AwsServiceWrapper struct {
	session *session.Session
}

func (s *AwsServiceWrapper) newSession() (*session.Session, error) {
	if s.session != nil {
		return s.session, nil
	}
	return session.NewSession(&aws.Config{})
}

// GetS3Object wraps S3.GetObject
func (s *AwsServiceWrapper) GetS3Object(bucket, key string) (io.ReadCloser, error) {
	sess, err := s.newSession()
	if err != nil {
		return nil, err
	}
	svc := s3.New(sess, &aws.Config{
		DisableRestProtocolURICleaning: aws.Bool(true),
	})
	resp, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// AssumeRole wraps Sts.AssumeRole
func (s *AwsServiceWrapper) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	sess, err := s.newSession()
	if err != nil {
		return nil, err
	}
	svc := sts.New(sess, &aws.Config{})
	return svc.AssumeRole(input)
}

// GetRole wraps IAM.GetRole
func (s *AwsServiceWrapper) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	sess, err := s.newSession()
	if err != nil {
		return nil, err
	}
	svc := iam.New(sess)
	return svc.GetRole(input)
}

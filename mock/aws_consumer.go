// Code generated by MockGen. DO NOT EDIT.
// Source: ../aws_consumer.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"
	auth "token_authorizer"

	sts "github.com/aws/aws-sdk-go/service/sts"
	gomock "github.com/golang/mock/gomock"
)

// MockAwsConsumerInterface is a mock of AwsConsumerInterface interface.
type MockAwsConsumerInterface struct {
	ctrl     *gomock.Controller
	recorder *MockAwsConsumerInterfaceMockRecorder
}

// MockAwsConsumerInterfaceMockRecorder is the mock recorder for MockAwsConsumerInterface.
type MockAwsConsumerInterfaceMockRecorder struct {
	mock *MockAwsConsumerInterface
}

// NewMockAwsConsumerInterface creates a new mock instance.
func NewMockAwsConsumerInterface(ctrl *gomock.Controller) *MockAwsConsumerInterface {
	mock := &MockAwsConsumerInterface{ctrl: ctrl}
	mock.recorder = &MockAwsConsumerInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAwsConsumerInterface) EXPECT() *MockAwsConsumerInterfaceMockRecorder {
	return m.recorder
}

// AssumeRole mocks base method.
func (m *MockAwsConsumerInterface) AssumeRole(ctx context.Context, rule *auth.Rule, name string) (*sts.Credentials, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssumeRole", ctx, rule, name)
	ret0, _ := ret[0].(*sts.Credentials)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AssumeRole indicates an expected call of AssumeRole.
func (mr *MockAwsConsumerInterfaceMockRecorder) AssumeRole(ctx, rule, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssumeRole", reflect.TypeOf((*MockAwsConsumerInterface)(nil).AssumeRole), ctx, rule, name)
}

// JwksURL mocks base method.
func (m *MockAwsConsumerInterface) JwksURL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "JwksURL")
	ret0, _ := ret[0].(string)
	return ret0
}

// JwksURL indicates an expected call of JwksURL.
func (mr *MockAwsConsumerInterfaceMockRecorder) JwksURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JwksURL", reflect.TypeOf((*MockAwsConsumerInterface)(nil).JwksURL))
}

// ReadConfiguration mocks base method.
func (m *MockAwsConsumerInterface) ReadConfiguration() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadConfiguration")
	ret0, _ := ret[0].(error)
	return ret0
}

// ReadConfiguration indicates an expected call of ReadConfiguration.
func (mr *MockAwsConsumerInterfaceMockRecorder) ReadConfiguration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadConfiguration", reflect.TypeOf((*MockAwsConsumerInterface)(nil).ReadConfiguration))
}

// RetrieveRulesFromRoleTags mocks base method.
func (m *MockAwsConsumerInterface) RetrieveRulesFromRoleTags(ctx context.Context, role string) ([]auth.Rule, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RetrieveRulesFromRoleTags", ctx, role)
	ret0, _ := ret[0].([]auth.Rule)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RetrieveRulesFromRoleTags indicates an expected call of RetrieveRulesFromRoleTags.
func (mr *MockAwsConsumerInterfaceMockRecorder) RetrieveRulesFromRoleTags(ctx, role interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RetrieveRulesFromRoleTags", reflect.TypeOf((*MockAwsConsumerInterface)(nil).RetrieveRulesFromRoleTags), ctx, role)
}

// Rules mocks base method.
func (m *MockAwsConsumerInterface) Rules() []auth.Rule {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Rules")
	ret0, _ := ret[0].([]auth.Rule)
	return ret0
}

// Rules indicates an expected call of Rules.
func (mr *MockAwsConsumerInterfaceMockRecorder) Rules() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rules", reflect.TypeOf((*MockAwsConsumerInterface)(nil).Rules))
}

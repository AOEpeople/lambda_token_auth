// Code generated by MockGen. DO NOT EDIT.
// Source: ../authorizer.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"
	token_authorizer "token_authorizer"

	gomock "github.com/golang/mock/gomock"
)

// MockAuthorizer is a mock of Authorizer interface.
type MockAuthorizer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizerMockRecorder
}

// MockAuthorizerMockRecorder is the mock recorder for MockAuthorizer.
type MockAuthorizerMockRecorder struct {
	mock *MockAuthorizer
}

// NewMockAuthorizer creates a new mock instance.
func NewMockAuthorizer(ctrl *gomock.Controller) *MockAuthorizer {
	mock := &MockAuthorizer{ctrl: ctrl}
	mock.recorder = &MockAuthorizerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizer) EXPECT() *MockAuthorizerMockRecorder {
	return m.recorder
}

// AwsConsumer mocks base method.
func (m *MockAuthorizer) AwsConsumer() token_authorizer.AwsConsumerInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AwsConsumer")
	ret0, _ := ret[0].(token_authorizer.AwsConsumerInterface)
	return ret0
}

// AwsConsumer indicates an expected call of AwsConsumer.
func (mr *MockAuthorizerMockRecorder) AwsConsumer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AwsConsumer", reflect.TypeOf((*MockAuthorizer)(nil).AwsConsumer))
}

// Config mocks base method.
func (m *MockAuthorizer) Config() *token_authorizer.Config {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config")
	ret0, _ := ret[0].(*token_authorizer.Config)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockAuthorizerMockRecorder) Config() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockAuthorizer)(nil).Config))
}

// TokenValidator mocks base method.
func (m *MockAuthorizer) TokenValidator() token_authorizer.TokenValidatorInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TokenValidator")
	ret0, _ := ret[0].(token_authorizer.TokenValidatorInterface)
	return ret0
}

// TokenValidator indicates an expected call of TokenValidator.
func (mr *MockAuthorizerMockRecorder) TokenValidator() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TokenValidator", reflect.TypeOf((*MockAuthorizer)(nil).TokenValidator))
}
package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type AuthorizerMock struct {
	mock.Mock
}

func NewAuthorizer() *AuthorizerMock {
	return &AuthorizerMock{}
}

func (m *AuthorizerMock) Authorize(req harbor.ScanRequest) (string, error) {
	args := m.Called(req)
	return args.Get(0).(string), args.Error(1)
}

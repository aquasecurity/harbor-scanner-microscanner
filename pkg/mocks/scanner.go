package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type ScannerMock struct {
	mock.Mock
}

func NewScanner() *ScannerMock {
	return &ScannerMock{}
}

func (m *ScannerMock) Scan(req harbor.ScanRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

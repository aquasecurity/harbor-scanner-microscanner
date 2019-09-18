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

func (m *ScannerMock) Scan(scanJobID string, req harbor.ScanRequest) error {
	args := m.Called(scanJobID, req)
	return args.Error(0)
}

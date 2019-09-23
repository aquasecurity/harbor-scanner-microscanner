package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/stretchr/testify/mock"
)

type TransformerMock struct {
	mock.Mock
}

func NewTransformer() *TransformerMock {
	return &TransformerMock{}
}

func (m *TransformerMock) Transform(req harbor.ScanRequest, sr *microscanner.ScanReport) (*harbor.VulnerabilityReport, error) {
	args := m.Called(req, sr)
	return args.Get(0).(*harbor.VulnerabilityReport), args.Error(1)
}

package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/stretchr/testify/mock"
)

type WrapperMock struct {
	mock.Mock
}

func NewWrapperMock() *WrapperMock {
	return &WrapperMock{}
}

func (m *WrapperMock) Run(image string) (*microscanner.ScanReport, error) {
	args := m.Called(image)
	return args.Get(0).(*microscanner.ScanReport), args.Error(1)
}

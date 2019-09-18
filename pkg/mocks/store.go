package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/stretchr/testify/mock"
)

type DataStoreMock struct {
	mock.Mock
}

func NewDataStore() *DataStoreMock {
	return &DataStoreMock{}
}

func (m *DataStoreMock) SaveScanJob(scanJob *job.ScanJob) error {
	args := m.Called(scanJob)
	return args.Error(0)
}

func (m *DataStoreMock) GetScanJob(scanJobID string) (*job.ScanJob, error) {
	args := m.Called(scanJobID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (m *DataStoreMock) UpdateStatus(scanJobID string, currentStatus, newStatus job.ScanJobStatus) error {
	args := m.Called(scanJobID, currentStatus, newStatus)
	return args.Error(0)
}

func (m *DataStoreMock) UpdateReports(scanJobID string, reports job.ScanReports) error {
	args := m.Called(scanJobID, reports)
	return args.Error(0)
}

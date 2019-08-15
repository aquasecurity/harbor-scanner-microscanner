package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type DataStoreMock struct {
	mock.Mock
}

func NewDataStore() *DataStoreMock {
	return &DataStoreMock{}
}

func (m *DataStoreMock) SaveScanJob(scanID uuid.UUID, scanJob *job.ScanJob) error {
	args := m.Called(scanID, scanJob)
	return args.Error(0)
}

func (m *DataStoreMock) GetScanJob(scanID uuid.UUID) (*job.ScanJob, error) {
	args := m.Called(scanID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (m *DataStoreMock) UpdateScanJobStatus(scanID uuid.UUID, currentStatus, newStatus job.ScanJobStatus) error {
	args := m.Called(scanID, currentStatus, newStatus)
	return args.Error(0)
}

func (m *DataStoreMock) SaveScanReports(scanID uuid.UUID, scanReports *store.ScanReports) error {
	args := m.Called(scanID, scanReports)
	return args.Error(0)
}

func (m *DataStoreMock) GetScanReports(scanID uuid.UUID) (*store.ScanReports, error) {
	args := m.Called(scanID)
	return args.Get(0).(*store.ScanReports), args.Error(1)
}

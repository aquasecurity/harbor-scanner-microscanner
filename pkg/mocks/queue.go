package mocks

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type JobQueueMock struct {
	mock.Mock
}

func NewJobQueue() *JobQueueMock {
	return &JobQueueMock{}
}

func (m *JobQueueMock) Start() {
	m.Called()
}

func (m *JobQueueMock) Stop() {
	m.Called()
}

func (m *JobQueueMock) EnqueueScanJob(sr harbor.ScanRequest) (*job.ScanJob, error) {
	args := m.Called(sr)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (m *JobQueueMock) GetScanJob(scanRequestID uuid.UUID) (*job.ScanJob, error) {
	args := m.Called(scanRequestID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

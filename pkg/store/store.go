package store

import (
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/google/uuid"
)

// DataStore defines methods for saving and retrieving scan results.
//
// Save saves the given ScanResult with the given scanID.
// Get retrieves ScanResult for the given scanID.
type DataStore interface {
	Save(scanID uuid.UUID, hsr *harbor.ScanResult) error
	Get(scanID uuid.UUID) (*harbor.ScanResult, error)
}

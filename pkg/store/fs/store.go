package fs

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"io/ioutil"
	"os"
	"path/filepath"
)

type fsStore struct {
	dataDir string
}

// NewStore constructs a ResultStore which stores scan results in the given directory on a local file system.
func NewStore(dataDir string) (store.DataStore, error) {
	if dataDir == "" {
		return nil, errors.New("dataDir must not be nil")
	}
	return &fsStore{dataDir: dataDir}, nil
}

func (rs *fsStore) Save(scanID uuid.UUID, hsr *harbor.ScanResult) error {
	resultAsJSON, err := json.MarshalIndent(hsr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling scan result: %v", err)
	}

	err = ioutil.WriteFile(rs.getFilePathFor(scanID), resultAsJSON, 0644)
	if err != nil {
		return fmt.Errorf("writing scan result to file: %v", err)
	}

	return nil
}

func (rs *fsStore) Get(scanID uuid.UUID) (*harbor.ScanResult, error) {
	file, err := os.Open(rs.getFilePathFor(scanID))
	if err != nil {
		return nil, fmt.Errorf("opening scan result file: %v", err)
	}

	var data harbor.ScanResult
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling scan result: %v", err)
	}

	return &data, nil
}

func (rs *fsStore) getFilePathFor(scanID uuid.UUID) string {
	return filepath.Join(rs.dataDir, scanID.String()+".json")
}

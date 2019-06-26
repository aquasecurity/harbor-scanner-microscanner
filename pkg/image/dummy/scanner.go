package dummy

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/microscanner-proxy/pkg/image"
	"github.com/aquasecurity/microscanner-proxy/pkg/model"
	"os"
)

type dummyScanner struct {
	data model.ScanResult
}

func NewScanner(dataFile string) (image.Scanner, error) {
	file, err := os.Open(dataFile)
	if err != nil {
		return nil, fmt.Errorf("opening data file: %v", err)
	}
	var data model.ScanResult
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("decoding data file: %v", err)
	}
	return &dummyScanner{
		data: data,
	}, nil
}

func (s *dummyScanner) Scan(req model.ScanRequest) error {
	fmt.Printf("I should do actual scanning at some point %v", req)
	return nil
}

func (s *dummyScanner) GetResults(correlationID string) (*model.ScanResult, error) {
	return &s.data, nil
}

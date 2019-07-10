package dummy

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/microscanner-proxy/pkg/image"
	"github.com/aquasecurity/microscanner-proxy/pkg/model"
	"github.com/danielpacak/docker-registry-client/pkg/auth"
	"github.com/danielpacak/docker-registry-client/pkg/registry"
	"log"
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
	client, err := registry.NewClient(req.RegistryURL, auth.NewBearerTokenAuthorizer(req.RegistryToken))
	if err != nil {
		return fmt.Errorf("constructing registry client: %v", err)
	}
	log.Printf("Saving image %s:%s", req.Repository, req.Digest)
	fsRoot, err := client.SaveImage(req.Repository, req.Digest, "/tmp/docker")
	if err != nil {
		return fmt.Errorf("saving image: %v", err)
	}

	log.Printf("Image saved to %s", fsRoot)

	return nil
}

func (s *dummyScanner) GetResult(digest string) (*model.ScanResult, error) {
	return &s.data, nil
}

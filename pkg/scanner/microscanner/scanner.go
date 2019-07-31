package microscanner

import (
	"errors"
	"fmt"
	"github.com/danielpacak/harbor-scanner-contract/pkg/image"
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/etc"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"log"
)

type imageScanner struct {
	cfg         *etc.Config
	wrapper     *Wrapper
	transformer model.Transformer
	store       store.DataStore
}

func NewScanner(cfg *etc.Config, transformer model.Transformer, store store.DataStore) (image.Scanner, error) {
	return &imageScanner{
		cfg:         cfg,
		transformer: transformer,
		store:       store,
		wrapper:     NewWrapper(cfg),
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	scanID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	log.Printf("RegistryURL: %s", req.RegistryURL)
	log.Printf("Repository: %s", req.Repository)
	log.Printf("Tag: %s", req.Tag)
	log.Printf("Digest: %s", req.Digest)
	log.Printf("Scan request %s", scanID.String())

	registryURL := req.RegistryURL
	if s.cfg.RegistryURL != "" {
		log.Printf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.RegistryURL)
		registryURL = s.cfg.RegistryURL
	}

	// TODO Use image digest instead of Tag
	imageToScan := fmt.Sprintf("%s/%s:%s", registryURL, req.Repository, req.Tag)
	sr, err := s.wrapper.Run(imageToScan)
	if err != nil {
		return nil, err
	}

	hsr, err := s.transformer.Transform(sr)
	if err != nil {
		return nil, err
	}

	err = s.store.Save(scanID, hsr)
	if err != nil {
		return nil, err
	}

	return &harbor.ScanResponse{
		DetailsKey: scanID.String(),
	}, nil
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	if detailsKey == "" {
		return nil, errors.New("detailsKey must not be nil")
	}

	scanID, err := uuid.Parse(detailsKey)
	if err != nil {
		return nil, err
	}

	return s.store.Get(scanID)
}

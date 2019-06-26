package model

type ScanRequest struct {
	CorrelationID string `json:"correlation_id"`
	RegistryURL   string `json:"registry_url"`
	RegistryToken string `json:"registry_token"`
	Repository    string `json:"repository"`
	Tag           string `json:"tag"`
	Digest        string `json:"digest"`
}

type ScanResult struct {
	Digest    string         `json:"digest"`
	OS        string         `json:"os"`
	Version   string         `json:"version"`
	Resources []ResourceScan `json:"resources"`
	Summary   Summary        `json:"vulnerability_summary"`
}

type ResourceScan struct {
	Resource        Resource        `json:"resource"`
	Scanned         bool            `json:"scanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Resource struct {
	Format   string `json:"format"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	CPE      string `json:"cpe"`
	NameHash string `json:"name_hash"`
	License  string `json:"license"`
}

type Vulnerability struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	VendorURL      string `json:"vendor_url"`
	VendorSeverity string `json:"vendor_severity"`
	Classification string `json:"classification"`
	NVDURL         string `json:"nvd_url"`
}

type Summary struct {
	Total      int `json:"total"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Sensitive  int `json:"sensitive"`
	Malware    int `json:"malware"`
}

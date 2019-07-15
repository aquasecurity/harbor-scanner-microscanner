package microscanner

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
	Name             string `json:"name"`
	Description      string `json:"description"`
	VendorURL        string `json:"vendor_url"`
	VendorSeverity   string `json:"vendor_severity"`
	VendorSeverityV3 string `json:"vendor_severity_v3"`
	Classification   string `json:"classification"`
	FixVersion       string `json:"fix_version"`
	NVDURL           string `json:"nvd_url"`
	NVDSeverity      string `json:"nvd_severity"`
	NVDSeverityV3    string `json:"nvd_severity_v3"`
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

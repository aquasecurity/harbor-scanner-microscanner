package harbor

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevNone
	SevUnknown
	SevLow
	SevMedium
	SevHigh
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

// Artifact is an artifact stored in a Harbor registry.
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type ScanRequest struct {
	ID       string   `json:"id"`
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

type VulnerabilityReport struct {
	Severity        Severity             `json:"severity"`
	Vulnerabilities []*VulnerabilityItem `json:"vulnerabilities"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
	Fixed       string   `json:"fixedVersion,omitempty"`
}

type ScannerMetadata struct {
	Name         string        `json:"name"`
	Vendor       string        `json:"vendor"`
	Version      string        `json:"version"`
	Capabilities []*Capability `json:"capabilities"`
}

type Capability struct {
	ArtifactMIMETypes []string `json:"artifact_mime_types"`
	ReportMIMETypes   []string `json:"report_mime_types"`
}

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

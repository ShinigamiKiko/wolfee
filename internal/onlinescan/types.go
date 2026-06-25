package onlinescan

const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"

	SevUnknown      = ""
	SevUnknownLabel = "UNKNOWN"
)

const (
	SeveritySourceOSV           = "OSV"
	SeveritySourceNVD           = "NVD"
	SeveritySourceDebianTracker = "debian-tracker"

	SeveritySourceTrivyDB = "trivy-db"
)

type Vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVSSVector  string   `json:"cvssVector,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	Published   string   `json:"published,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Fixed       []string `json:"fixed,omitempty"`
	Reference   string   `json:"reference,omitempty"`

	InKEV          bool     `json:"inKev"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epssPercentile,omitempty"`
	PoCs           []string `json:"pocs,omitempty"`

	Reachable string `json:"reachable,omitempty"`

	CallSite string `json:"callSite,omitempty"`

	CallLine string `json:"callLine,omitempty"`

	VulnerableSymbols []VulnImport `json:"vulnerableSymbols,omitempty"`

	SeveritySource string `json:"severitySource,omitempty"`

	Status string `json:"status,omitempty"`

	DistroStatus []DistroStatus `json:"distroStatus,omitempty"`

	RelatedAdvisories []string `json:"relatedAdvisories,omitempty"`
}

type VulnImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

type DistroStatus struct {
	Distro     string `json:"distro"`
	Release    string `json:"release,omitempty"`
	Status     string `json:"status"`
	FixVersion string `json:"fixVersion,omitempty"`
	Urgency    string `json:"urgency,omitempty"`

	Source string `json:"source,omitempty"`
}

type Malware struct {
	Found     bool     `json:"found"`
	ID        string   `json:"id,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Reference string   `json:"reference,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	MalIDs    []string `json:"malIds,omitempty"`
}

type Toxic struct {
	Found      bool     `json:"found"`
	Categories []string `json:"categories,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

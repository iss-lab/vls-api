package models

type Vulnerability struct {
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Severity string `json:"severity"`
}

type ScanResults struct {
	PackageName        string             `json:"package_name"`
	VulnerableVersions map[string]Version `json:"vulnerable_versions"`
}

type Version struct {
	OverallSeverity string          `json:"overall_severity"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type ScanResponse struct {
	ScanResults []ScanResults `json:"scan_results"`
}

type PayloadForNoVersion struct {
	Package InputWithoutVersion `json:"package"`
}

type InputWithoutVersion struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type ScanRequests struct {
	ScanRequest []InputWithVersion `json:"scan_request"`
}

type InputWithVersion struct {
	Version   string `json:"version"`
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type ScanResult struct {
	PackageDetails struct {
		Name                 string `json:"name"`
		ScanVersionRequested string `json:"scan_version_requested"`
		VersionScanned       string `json:"version_scanned"`
		Ecosystem            string `json:"ecosystem"`
	} `json:"package_details"`
	Source          string            `json:"source"`
	VlsSource       string            `json:"vls_source"`
	Error           string            `json:"error"`
	Vulnerabilities []Vulnerabilities `json:"vulnerabilities"`
}

type PayloadForVersion struct {
	Version string  `json:"version"`
	Package Package `json:"package"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type ErrorResponse struct {
	Message string `json:"error_message"`
}

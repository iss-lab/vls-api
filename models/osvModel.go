package models

type OsvResponseNPM struct {
	Vulns []VulnerabilitiesNPM `json:"vulns"`
}
type VulnerabilitiesNPM struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Modified         string           `json:"modified"`
	Published        string           `json:"published"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	References       []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	} `json:"affected"`
	SeverityObject []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	SchemaVersion string `json:"schema_version"`
}
type DatabaseSpecific struct {
	CWEIDs           []string `json:"cwe_ids"`
	Severity         string   `json:"severity"`
	GithubReviewed   bool     `json:"github_reviewed"`
	GithubReviewedAt string   `json:"github_reviewed_at"`
	NVDPublishedAt   string   `json:"nvd_published_at"`
}

type Vulnerabilities struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Aliases          []string         `json:"aliases"`
	Published        string           `json:"published"`
	Modified         string           `json:"modified"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`

	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
			Type   string              `json:"type"`
			Repo   string              `json:"repo"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	SeverityObject []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type OsvResponse struct {
	Vulns []Vulnerabilities `json:"vulns"`
}

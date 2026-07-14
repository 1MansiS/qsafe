package findings

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type Finding struct {
	Primitive string   `json:"primitive"`
	Usage     string   `json:"usage"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
	Severity  Severity `json:"severity"`
	Detail    string   `json:"detail,omitempty"`
}

type FindingSet struct {
	Findings []Finding `json:"findings"`
}

type CodebaseReport struct {
	Root              string         `json:"root"`
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	ByPrimitive       map[string]int `json:"by_primitive"`
	Findings          []Finding      `json:"findings"`
}

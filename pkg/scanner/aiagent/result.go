package aiagent

type Detection struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Version  string `json:"version,omitempty"`
	PURL     string `json:"purl,omitempty"`
	FilePath string `json:"file_path,omitempty"`
}

type AgentResult struct {
	AgentID    string      `json:"agent_id"`
	Name       string      `json:"name"`
	Category   string      `json:"category"`
	Platform   string      `json:"platform"`
	Detections []Detection `json:"detections"`
}

func (r AgentResult) DataType() string {
	return "AIAGENT"
}

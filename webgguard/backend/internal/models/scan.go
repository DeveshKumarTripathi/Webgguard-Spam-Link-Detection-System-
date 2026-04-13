// Package models defines the data structures used across the WebGGuard backend.
// These are shared types that flow through the API → Service → Rules pipeline.
package models

// ScanRequest is the incoming JSON body from the frontend.
// Example: { "url": "https://example.com" }
type ScanRequest struct {
	URL string `json:"url"`
}

// VirusTotalStats holds the raw detection counts returned by the VirusTotal API.
// These are extracted from the "last_analysis_stats" field in the VT response.
type VirusTotalStats struct {
	Malicious   int `json:"malicious"`
	Suspicious  int `json:"suspicious"`
	Undetected  int `json:"undetected"`
	Harmless    int `json:"harmless"`
	Timeout     int `json:"timeout"`
}

// ScanResult is the final response sent back to the frontend.
// It combines the verdict, a 0-100 risk score, and a confidence percentage.
type ScanResult struct {
	Verdict    string          `json:"verdict"`    // "safe", "suspicious", or "malicious"
	RiskScore  int             `json:"riskScore"`  // 0 (safe) → 100 (dangerous)
	Confidence int             `json:"confidence"` // How confident the rule engine is (0-100%)
	Stats      VirusTotalStats `json:"stats"`      // Raw VT stats, useful for debugging / UI details
}

// ErrorResponse is returned when something goes wrong.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// Package services contains external API integrations.
// The VirusTotal service is responsible for querying the VT v3 API
// and returning normalized scan statistics.
package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"webgguard/internal/models"
	"webgguard/internal/utils"
)

const (
	vtBaseURL = "https://www.virustotal.com/api/v3/urls"

	// httpTimeout prevents the backend from hanging indefinitely on slow VT responses.
	// TODO: Make this configurable via environment variable.
	httpTimeout = 15 * time.Second
)

// VirusTotalService wraps the HTTP client and API key.
// Using a struct (rather than bare functions) makes it easy to mock in tests.
//
// TODO: Add rate-limit handling — VT free tier allows 4 requests/minute.
// TODO: Add response caching (e.g., Redis or in-memory TTL cache) to avoid
//       redundant API calls for recently-scanned URLs.
type VirusTotalService struct {
	APIKey     string
	HTTPClient *http.Client
}

// NewVirusTotalService creates a ready-to-use VT service.
// Call this once at startup and inject it into your handlers.
func NewVirusTotalService(apiKey string) *VirusTotalService {
	return &VirusTotalService{
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

// vtURLReport mirrors the portion of the VirusTotal v3 API response we care about.
// The full response is much larger; we only decode what we need.
// Reference: https://developers.virustotal.com/reference/url-object
type vtURLReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetURLStats fetches analysis stats for the given URL from VirusTotal.
// It returns a VirusTotalStats struct that the rule engine can consume.
func (vt *VirusTotalService) GetURLStats(rawURL string) (models.VirusTotalStats, error) {
	// Encode the URL into the VT-specific base64url identifier format
	urlID := utils.EncodeURLForVirusTotal(rawURL)

	endpoint := fmt.Sprintf("%s/%s", vtBaseURL, urlID)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return models.VirusTotalStats{}, fmt.Errorf("failed to build VT request: %w", err)
	}

	// VT v3 API uses the x-apikey header for authentication
	req.Header.Set("x-apikey", vt.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := vt.HTTPClient.Do(req)
	if err != nil {
		return models.VirusTotalStats{}, fmt.Errorf("VT API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle non-200 responses from VT
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return models.VirusTotalStats{}, fmt.Errorf("VT returned status %d: %s", resp.StatusCode, string(body))
	}

	var report vtURLReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return models.VirusTotalStats{}, fmt.Errorf("failed to decode VT response: %w", err)
	}

	// Map the VT response into our clean internal model
	stats := models.VirusTotalStats{
		Malicious:  report.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious: report.Data.Attributes.LastAnalysisStats.Suspicious,
		Undetected: report.Data.Attributes.LastAnalysisStats.Undetected,
		Harmless:   report.Data.Attributes.LastAnalysisStats.Harmless,
		Timeout:    report.Data.Attributes.LastAnalysisStats.Timeout,
	}

	return stats, nil
}

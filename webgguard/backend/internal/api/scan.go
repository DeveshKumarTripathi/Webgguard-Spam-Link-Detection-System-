// Package api contains HTTP handlers for WebGGuard endpoints.
//
// The handler here acts as a thin orchestration layer:
//   1. Parse & validate the request
//   2. Call the VirusTotal service
//   3. Pass results to the rule engine
//   4. Return the final verdict JSON
//
// Business logic lives in services/ and rules/ — NOT here.
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"webgguard/internal/models"
	"webgguard/internal/rules"
	"webgguard/internal/services"
	"webgguard/internal/utils"
)

// ScanHandler holds dependencies needed to process scan requests.
// Using dependency injection makes this easy to test with a mock VT service.
type ScanHandler struct {
	VTService *services.VirusTotalService
}

// NewScanHandler constructs a ScanHandler with a real VirusTotal service.
func NewScanHandler(vtService *services.VirusTotalService) *ScanHandler {
	return &ScanHandler{VTService: vtService}
}

// HandleScan is the HTTP handler for POST /scan.
// It orchestrates the full pipeline: validate → fetch VT stats → evaluate → respond.
func (h *ScanHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Only POST is allowed", "")
		return
	}

	// --- Step 1: Parse the request body ---
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body", err.Error())
		return
	}

	// --- Step 2: Validate & normalize the URL ---
	cleanURL, err := utils.NormalizeURL(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid URL", err.Error())
		return
	}

	log.Printf("[SCAN] Scanning URL: %s", cleanURL)

	// --- Step 3: Fetch stats from VirusTotal ---
	stats, err := h.VTService.GetURLStats(cleanURL)
	if err != nil {
		log.Printf("[ERROR] VT service failed for %s: %v", cleanURL, err)
		writeError(w, http.StatusInternalServerError, "VirusTotal lookup failed", err.Error())
		return
	}

	// --- Step 4: Run through the rule engine ---
	result := rules.Evaluate(stats)

	log.Printf("[RESULT] %s → verdict=%s score=%d confidence=%d",
		cleanURL, result.Verdict, result.RiskScore, result.Confidence)

	// --- Step 5: Respond with JSON ---
	writeJSON(w, http.StatusOK, result)
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[ERROR] Failed to encode JSON response: %v", err)
	}
}

// writeError sends a structured error response.
func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, models.ErrorResponse{
		Error:   message,
		Details: details,
	})
}

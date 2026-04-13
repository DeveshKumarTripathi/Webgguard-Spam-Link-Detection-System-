// Package rules implements the WebGGuard verdict engine.
//
// This is the "brain" of the application. It takes raw VirusTotal stats
// and applies a scoring formula to produce a human-readable verdict,
// a 0–100 risk score, and a confidence percentage.
//
// ──────────────────────────────────────────────
//  HOW THE SCORING WORKS
// ──────────────────────────────────────────────
//
//  1. Total engines  = malicious + suspicious + undetected + harmless + timeout
//  2. Detection ratio = (malicious + suspicious) / total engines
//  3. Base score      = detection ratio × 100
//  4. Penalty weights:
//     - Each malicious detection  → +3 pts (hard signal)
//     - Each suspicious detection → +1 pt  (soft signal)
//  5. Score is clamped to [0, 100]
//  6. Verdict thresholds:
//     - score ≥ 60  → malicious
//     - score ≥ 20  → suspicious
//     - score <  20  → safe
//  7. Confidence = harmless / total engines × 100
//     (How many engines actively vouched for the URL)
//
// TODO: Replace numeric thresholds with a config file so analysts can
//       tune them without recompiling the binary.
// TODO: Add reputation factors (domain age, TLD, IP geolocation, etc.)
// TODO: Consider a machine-learning scoring layer on top of the rule engine.
package rules

import "webgguard/internal/models"

// Verdict constants — use these strings in the UI and API responses.
const (
	VerdictSafe       = "safe"
	VerdictSuspicious = "suspicious"
	VerdictMalicious  = "malicious"
)

// Scoring weights — adjust these to tune sensitivity.
// Higher maliciousWeight means a single bad detection raises the score more.
const (
	maliciousWeight  = 3.0 // Each malicious detection contributes 3x
	suspiciousWeight = 1.0 // Each suspicious detection contributes 1x
)

// Verdict threshold boundaries
const (
	maliciousThreshold  = 60 // score >= this → malicious
	suspiciousThreshold = 20 // score >= this → suspicious (else safe)
)

// Evaluate takes VirusTotal stats and returns a complete ScanResult.
// This is the only exported function in the rules package — the API handler
// calls this after receiving stats from the VT service.
func Evaluate(stats models.VirusTotalStats) models.ScanResult {
	totalEngines := stats.Malicious + stats.Suspicious + stats.Undetected +
		stats.Harmless + stats.Timeout

	// Guard against division by zero if VT returns no engine data
	if totalEngines == 0 {
		return models.ScanResult{
			Verdict:    VerdictSuspicious,
			RiskScore:  50,
			Confidence: 0,
			Stats:      stats,
		}
	}

	// Step 1: Calculate the base detection ratio score (0–100)
	detections := float64(stats.Malicious + stats.Suspicious)
	detectionRatio := detections / float64(totalEngines)
	baseScore := detectionRatio * 100

	// Step 2: Apply penalty weights on top of the ratio score
	weightedPenalty := float64(stats.Malicious)*maliciousWeight +
		float64(stats.Suspicious)*suspiciousWeight

	// Blend base score with weighted penalty (equal weight blend)
	// TODO: Experiment with different blend ratios or pure-penalty scoring.
	rawScore := (baseScore + weightedPenalty) / 2.0

	// Step 3: Clamp score to [0, 100]
	riskScore := clamp(int(rawScore), 0, 100)

	// Step 4: Calculate confidence based on how many engines gave a clear verdict
	// Engines that timed out or gave no result reduce our confidence.
	activeEngines := stats.Malicious + stats.Suspicious + stats.Harmless
	confidence := 0
	if activeEngines > 0 {
		confidence = clamp(int(float64(activeEngines)/float64(totalEngines)*100), 0, 100)
	}

	// Step 5: Map score to verdict
	verdict := scoreToVerdict(riskScore)

	return models.ScanResult{
		Verdict:    verdict,
		RiskScore:  riskScore,
		Confidence: confidence,
		Stats:      stats,
	}
}

// scoreToVerdict maps a numeric risk score to a named verdict.
func scoreToVerdict(score int) string {
	switch {
	case score >= maliciousThreshold:
		return VerdictMalicious
	case score >= suspiciousThreshold:
		return VerdictSuspicious
	default:
		return VerdictSafe
	}
}

// clamp keeps an integer value within [min, max].
func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

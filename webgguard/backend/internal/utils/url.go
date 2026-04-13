// Package utils provides helper functions used throughout WebGGuard.
package utils

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeURL ensures the URL has a scheme (defaults to https) and is well-formed.
// VirusTotal requires a clean URL, so we validate before sending anything upstream.
//
// TODO: Add additional sanitization (e.g., strip tracking params, normalize path casing)
func NormalizeURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	// Add https:// if no scheme is present
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	// Ensure there is at least a hostname
	if parsed.Host == "" {
		return "", fmt.Errorf("URL is missing a hostname")
	}

	return parsed.String(), nil
}

// EncodeURLForVirusTotal converts a URL to the base64url-encoded identifier
// required by the VirusTotal v3 API.
//
// VT uses base64url (URL-safe base64 WITHOUT padding) as the lookup key for URLs.
// Reference: https://developers.virustotal.com/reference/url
func EncodeURLForVirusTotal(rawURL string) string {
	encoded := base64.URLEncoding.EncodeToString([]byte(rawURL))
	// Strip trailing '=' padding characters — VT does not accept them
	return strings.TrimRight(encoded, "=")
}

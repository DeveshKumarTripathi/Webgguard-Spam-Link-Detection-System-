// WebGGuard Backend — Entry Point
//
// This file wires everything together:
//   - Reads config from environment variables
//   - Creates the VirusTotal service
//   - Registers HTTP routes
//   - Starts the server
//
// Run with:
//   VT_API_KEY=your_key_here go run ./cmd/server
package main

import (
	"log"
	"net/http"
	"os"

	"webgguard/internal/api"
	"webgguard/internal/services"
)

const (
	defaultPort = "8080"
)

func main() {
	// --- Configuration ---
	// All secrets come from environment variables — never hardcode them.
	// TODO: Consider using a proper config library (e.g., viper) for larger projects.
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("[FATAL] VT_API_KEY environment variable is not set. " +
			"Get a free key at https://www.virustotal.com/gui/join-us")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// --- Dependency construction ---
	// Build services and handlers. In a larger app, use a DI framework.
	vtService := services.NewVirusTotalService(apiKey)
	scanHandler := api.NewScanHandler(vtService)

	// --- Router setup ---
	// Using the standard library mux for simplicity.
	// TODO: Replace with chi or gorilla/mux if you need middleware, path params, etc.
	mux := http.NewServeMux()

	// POST /scan — the main endpoint
	mux.HandleFunc("/scan", scanHandler.HandleScan)

	// GET /health — simple liveness check for load balancers / Docker health checks
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// --- CORS middleware ---
	// Wraps all routes to allow the React dev server (localhost:5173) to call the API.
	// TODO: In production, restrict AllowedOrigins to your actual frontend domain.
	handler := corsMiddleware(mux)

	// --- Start server ---
	addr := ":" + port
	log.Printf("[START] WebGGuard backend listening on http://localhost%s", addr)
	log.Printf("[INFO]  Endpoint: POST http://localhost%s/scan", addr)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}

// corsMiddleware adds the CORS headers required for the React frontend to
// communicate with this backend during local development.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow the Vite dev server origin
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight (OPTIONS) requests sent by browsers before POST
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

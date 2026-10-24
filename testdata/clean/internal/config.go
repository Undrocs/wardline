package internal

import "os"

// Credentials are read from the environment, never hardcoded.
func DatabaseURL() string {
	return os.Getenv("DATABASE_URL")
}

func apiKey() string { return os.Getenv("API_KEY") }

const (
	// Documentation placeholder, not a credential.
	examplePassword = "changeme"
)

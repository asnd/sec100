package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"3gpp-scanner/internal/models"
)

const (
	DefaultMCCMNCURL = "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"
	CacheFileName    = "mcc-mnc-list.json"
)

// Fetcher handles fetching and caching of MCC-MNC data
type Fetcher struct {
	URL      string
	CacheDir string
	CacheTTL time.Duration
	Verbose  bool
}

// NewFetcher creates a new MCC-MNC fetcher
func NewFetcher(url, cacheDir string, cacheTTL time.Duration, verbose bool) *Fetcher {
	if url == "" {
		url = DefaultMCCMNCURL
	}
	if cacheDir == "" {
		cacheDir = "."
	}
	return &Fetcher{
		URL:      url,
		CacheDir: cacheDir,
		CacheTTL: cacheTTL,
		Verbose:  verbose,
	}
}

// Fetch retrieves the MCC-MNC list, using cache if available and fresh
func (f *Fetcher) Fetch() ([]models.MCCMNCEntry, error) {
	cachePath := filepath.Join(f.CacheDir, CacheFileName)

	// Check if cache exists and is fresh
	if f.isCacheFresh(cachePath) {
		if f.Verbose {
			fmt.Printf("Using cached MCC-MNC list from %s\n", cachePath)
		}
		return f.readFromFile(cachePath)
	}

	// Fetch from URL
	if f.Verbose {
		fmt.Printf("Fetching MCC-MNC list from %s\n", f.URL)
	}

	entries, err := f.fetchFromURL()
	if err != nil {
		// If fetch fails, try to use stale cache
		if _, statErr := os.Stat(cachePath); statErr == nil {
			if f.Verbose {
				fmt.Printf("Warning: fetch failed, using stale cache: %v\n", err)
			}
			return f.readFromFile(cachePath)
		}
		return nil, fmt.Errorf("failed to fetch MCC-MNC list: %w", err)
	}

	// Save to cache
	if err := f.saveToCache(cachePath, entries); err != nil {
		if f.Verbose {
			fmt.Printf("Warning: failed to save cache: %v\n", err)
		}
	}

	return entries, nil
}

// FetchFromFile reads MCC-MNC list from a local file
func (f *Fetcher) FetchFromFile(filePath string) ([]models.MCCMNCEntry, error) {
	if f.Verbose {
		fmt.Printf("Reading MCC-MNC list from %s\n", filePath)
	}
	return f.readFromFile(filePath)
}

// fetchFromURL downloads the MCC-MNC list from the remote URL
func (f *Fetcher) fetchFromURL() ([]models.MCCMNCEntry, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(f.URL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var entries []models.MCCMNCEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return entries, nil
}

// readFromFile reads and parses the MCC-MNC list from a file
func (f *Fetcher) readFromFile(filePath string) ([]models.MCCMNCEntry, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var entries []models.MCCMNCEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return entries, nil
}

// saveToCache saves the MCC-MNC list to the cache file
func (f *Fetcher) saveToCache(filePath string, entries []models.MCCMNCEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// isCacheFresh checks if the cache file exists and is within TTL
func (f *Fetcher) isCacheFresh(filePath string) bool {
	if f.CacheTTL == 0 {
		return false // Cache disabled
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return false // Cache doesn't exist
	}

	age := time.Since(info.ModTime())
	return age < f.CacheTTL
}

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Matches bootstrap-server.py: /trcs returns [{"id":{"isd":..,"base_number":..,"serial_number":..}}]
type trcListItem struct {
	ID trcID `json:"id"`
}

type trcID struct {
	ISD        int `json:"isd"`
	BaseNumber int `json:"base_number"`
	Serial     int `json:"serial_number"`
}

// BootstrapFetch downloads topology.json and TRCs from a SCION bootstrap server
// and writes them into configDir in the layout expected by NewSciondRetriever:
//
//	configDir/topology.json
//	configDir/certs/ISD{isd}-B{base}-S{serial}.trc
//
// baseURL examples:
//
//	http://10.0.0.1:8042
//	https://bootstrap.example.org:443
func BootstrapFetch(ctx context.Context, baseURL, configDir string) error {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return fmt.Errorf("bootstrap baseURL is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid bootstrap baseURL %q: %w", baseURL, err)
	}
	if u.Scheme == "" {
		// allow "host:port" and treat as http
		u.Scheme = "http"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported bootstrap scheme %q (want http/https)", u.Scheme)
	}
	// normalize: remove trailing slash
	u.Path = strings.TrimRight(u.Path, "/")
	base := u.String()

	// Ensure dirs exist
	if err := os.MkdirAll(filepath.Join(configDir, "certs"), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	client := &http.Client{
		Timeout: 8 * time.Second, // keep small; you can tune
	}

	// 1) topology.json
	topoBytes, err := httpGet(ctx, client, base+"/topology", "application/json")
	if err != nil {
		return fmt.Errorf("fetch /topology: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(configDir, "topology.json"), topoBytes, 0o644); err != nil {
		return fmt.Errorf("write topology.json: %w", err)
	}

	// 2) trcs list
	trcListBytes, err := httpGet(ctx, client, base+"/trcs", "application/json")
	if err != nil {
		return fmt.Errorf("fetch /trcs: %w", err)
	}
	var trcs []trcListItem
	if err := json.Unmarshal(trcListBytes, &trcs); err != nil {
		return fmt.Errorf("parse /trcs json: %w", err)
	}

	// 3) download each TRC blob
	for _, item := range trcs {
		id := item.ID
		blobURL := fmt.Sprintf("%s/trcs/isd%d-b%d-s%d/blob", base, id.ISD, id.BaseNumber, id.Serial)

		blobBytes, err := httpGet(ctx, client, blobURL, "") // script uses text/plain; accept anything
		if err != nil {
			return fmt.Errorf("fetch TRC blob (ISD%d-B%d-S%d): %w", id.ISD, id.BaseNumber, id.Serial, err)
		}

		// The script’s files are named like "ISD1-B1-S1.trc"
		name := fmt.Sprintf("ISD%d-B%d-S%d.trc", id.ISD, id.BaseNumber, id.Serial)
		outPath := filepath.Join(configDir, "certs", name)

		if err := atomicWriteFile(outPath, blobBytes, 0o644); err != nil {
			return fmt.Errorf("write TRC %s: %w", name, err)
		}
	}

	return nil
}

// httpGet downloads a URL and returns the body. If wantContentType != "",
// we require the Content-Type to contain that substring (best-effort).
func httpGet(ctx context.Context, client *http.Client, url string, wantContentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	if wantContentType != "" {
		ct := resp.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, wantContentType) {
			// not fatal if you want to be lenient, but I’d keep it strict for topology/trcs JSON
			return nil, fmt.Errorf("unexpected content-type %q (want contains %q)", ct, wantContentType)
		}
	}

	return io.ReadAll(resp.Body)
}

// atomicWriteFile writes data to a temp file then renames it.
// This avoids partially-written config if the process dies mid-write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp := filepath.Join(dir, "."+base+".tmp")

	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

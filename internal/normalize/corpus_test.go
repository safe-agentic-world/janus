package normalize

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const normalizationCorpusDigest = "308d66844a51a7506d1ff287acc435a7f8a12f23e073c727a609dca0bf5b4f60"

type corpusEntry struct {
	Name          string `json:"name"`
	Resource      string `json:"resource"`
	Normalized    string `json:"normalized,omitempty"`
	ErrorContains string `json:"error_contains,omitempty"`
}

func TestNormalizationGoldenCorpus(t *testing.T) {
	entries := loadCorpusEntries(t, "corpus.jsonl")
	if len(entries) < 250 {
		t.Fatalf("expected at least 250 corpus entries, got %d", len(entries))
	}
	for _, entry := range entries {
		got, err := normalizeCorpusResource(entry.Resource)
		if err != nil {
			t.Fatalf("%s: normalize: %v", entry.Name, err)
		}
		if got != entry.Normalized {
			t.Fatalf("%s: expected %s, got %s", entry.Name, entry.Normalized, got)
		}
	}
}

func TestNormalizationBypassCorpus(t *testing.T) {
	entries := loadCorpusEntries(t, "bypass_attempts.jsonl")
	if len(entries) == 0 {
		t.Fatal("expected bypass corpus entries")
	}
	for _, entry := range entries {
		got, err := normalizeCorpusResource(entry.Resource)
		if entry.ErrorContains != "" {
			if err == nil {
				t.Fatalf("%s: expected error containing %q, got normalized %s", entry.Name, entry.ErrorContains, got)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(entry.ErrorContains)) {
				t.Fatalf("%s: expected error containing %q, got %v", entry.Name, entry.ErrorContains, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: normalize: %v", entry.Name, err)
		}
		if got != entry.Normalized {
			t.Fatalf("%s: expected %s, got %s", entry.Name, entry.Normalized, got)
		}
	}
}

func TestNormalizationCorpusDigestStable(t *testing.T) {
	if normalizationCorpusDigest == "" {
		t.Fatal("normalizationCorpusDigest must be set")
	}
	hasher := sha256.New()
	for _, fileName := range []string{"corpus.jsonl", "bypass_attempts.jsonl"} {
		entries := loadCorpusEntries(t, fileName)
		for _, entry := range entries {
			got, err := normalizeCorpusResource(entry.Resource)
			if entry.ErrorContains != "" {
				if err == nil {
					t.Fatalf("%s: expected error", entry.Name)
				}
				_, _ = hasher.Write([]byte(entry.Name + "|ERR|" + err.Error() + "\n"))
				continue
			}
			if err != nil {
				t.Fatalf("%s: normalize: %v", entry.Name, err)
			}
			_, _ = hasher.Write([]byte(entry.Name + "|" + got + "\n"))
		}
	}
	gotDigest := hex.EncodeToString(hasher.Sum(nil))
	if gotDigest != normalizationCorpusDigest {
		t.Fatalf("expected digest %s, got %s", normalizationCorpusDigest, gotDigest)
	}
}

func normalizeCorpusResource(raw string) (string, error) {
	return NormalizeResource(raw)
}

func loadCorpusEntries(t *testing.T, fileName string) []corpusEntry {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "normalization", fileName)
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", fileName, err)
	}
	defer file.Close()

	var entries []corpusEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry corpusEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse %s: %v", fileName, err)
		}
		if entry.Name == "" || entry.Resource == "" {
			t.Fatalf("invalid corpus entry in %s: %+v", fileName, entry)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", fileName, err)
	}
	return entries
}

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func buildUpstreamEnvironment(config UpstreamServerConfig) ([]string, string) {
	effective := map[string]string{}
	allowlisted := uniqueSortedNames(config.EnvAllowlist)
	for _, key := range allowlisted {
		if value, ok := os.LookupEnv(key); ok {
			effective[key] = value
		}
	}
	overrides := uniqueSortedNames(mapKeys(config.Env))
	for _, key := range overrides {
		effective[key] = config.Env[key]
	}
	keys := make([]string, 0, len(effective))
	for key := range effective {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+effective[key])
	}
	return env, upstreamEnvShapeHash(keys)
}

func upstreamEnvShapeHash(keys []string) string {
	if len(keys) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	data := strings.Join(keys, "\x00")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func uniqueSortedNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		seen[name] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func mapKeys(in map[string]string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	return out
}

func isAbsoluteCommandPath(command string) bool {
	return filepath.IsAbs(strings.TrimSpace(command))
}

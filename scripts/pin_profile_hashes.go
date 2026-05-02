//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safe-agentic-world/nomos/internal/policy"
)

var profileNames = []string{"safe-dev", "ci-strict", "prod-locked"}

func main() {
	mustRun()
}

func mustRun() {
	if _, err := os.Stat("go.mod"); err != nil {
		fatalf("run from repository root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join("internal", "launcher", "embedded_profiles"), 0o755); err != nil {
		fatalf("create embedded profile dir: %v", err)
	}
	hashes := map[string]string{}
	for _, name := range profileNames {
		source := filepath.Join("profiles", name+".yaml")
		target := filepath.Join("internal", "launcher", "embedded_profiles", name+".yaml")
		data, err := os.ReadFile(source)
		if err != nil {
			fatalf("read %s: %v", source, err)
		}
		if err := writeIfChanged(target, data); err != nil {
			fatalf("write %s: %v", target, err)
		}
		bundle, err := policy.LoadBundle(source)
		if err != nil {
			fatalf("load %s: %v", source, err)
		}
		hashes[name] = bundle.Hash
	}
	if err := writeIfChanged(filepath.Join("testdata", "policy-profiles", "hashes.json"), profileHashesJSON(hashes)); err != nil {
		fatalf("write profile hashes: %v", err)
	}
}

func writeIfChanged(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func profileHashesJSON(hashes map[string]string) []byte {
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, name := range profileNames {
		comma := ","
		if i == len(profileNames)-1 {
			comma = ""
		}
		_, _ = fmt.Fprintf(&b, "  %q: %q%s\n", name, hashes[name], comma)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

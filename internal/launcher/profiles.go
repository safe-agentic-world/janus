package launcher

import (
	"fmt"
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/policy"
)

type EmbeddedProfile struct {
	Name    string
	Summary string
	Hash    string
}

func EmbeddedProfileNames() []string {
	summaries := profileSummaries()
	names := make([]string, 0, len(summaries))
	for name := range summaries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func EmbeddedProfileYAML(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	if _, ok := profileSummaries()[name]; !ok {
		return nil, fmt.Errorf("unknown profile %q: expected safe-dev, ci-strict, or prod-locked", name)
	}
	data, err := embeddedProfiles.ReadFile("embedded_profiles/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded profile %q: %w", name, err)
	}
	return append([]byte(nil), data...), nil
}

func EmbeddedProfileBundle(name string) (policy.Bundle, error) {
	data, err := EmbeddedProfileYAML(name)
	if err != nil {
		return policy.Bundle{}, err
	}
	return policy.LoadBundleBytes(data, name+".yaml")
}

func EmbeddedProfiles() ([]EmbeddedProfile, error) {
	names := EmbeddedProfileNames()
	out := make([]EmbeddedProfile, 0, len(names))
	for _, name := range names {
		bundle, err := EmbeddedProfileBundle(name)
		if err != nil {
			return nil, err
		}
		out = append(out, EmbeddedProfile{
			Name:    name,
			Summary: profileSummaries()[name],
			Hash:    bundle.Hash,
		})
	}
	return out, nil
}

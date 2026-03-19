package sandbox

import (
	"errors"
	"sort"
	"strings"
)

const (
	ProfileNone      = "none"
	ProfileLocal     = "local"
	ProfileContainer = "container"
)

var profileOrder = map[string]int{
	ProfileNone:      0,
	ProfileLocal:     1,
	ProfileContainer: 2,
}

type Evidence struct {
	ContainerBackendReady bool
	Rootless              bool
	ReadOnlyFS            bool
	NoNewPrivileges       bool
	NetworkDefaultDeny    bool
}

type Selection struct {
	Profile       string
	Backend       string
	WritablePaths []string
	NetworkEgress string
}

func NormalizeProfile(profile string) string {
	switch profile {
	case ProfileNone, ProfileLocal, ProfileContainer:
		return profile
	default:
		return ProfileNone
	}
}

func SelectProfile(obligations map[string]any, configured string) (string, error) {
	configured = NormalizeProfile(configured)
	required := requiredProfile(obligations)
	if profileOrder[required] > profileOrder[configured] {
		return ProfileNone, errors.New("sandbox profile required but not available")
	}
	if required == ProfileNone {
		return configured, nil
	}
	return required, nil
}

func SelectBackend(obligations map[string]any, configured string, evidence Evidence, writablePaths []string) (Selection, error) {
	profile, err := SelectProfile(obligations, configured)
	if err != nil {
		return Selection{}, err
	}
	switch profile {
	case ProfileNone:
		return Selection{
			Profile:       ProfileNone,
			Backend:       ProfileNone,
			WritablePaths: nil,
			NetworkEgress: "inherit",
		}, nil
	case ProfileLocal:
		return Selection{
			Profile:       ProfileLocal,
			Backend:       ProfileLocal,
			WritablePaths: normalizeWritablePaths(writablePaths),
			NetworkEgress: "best_effort",
		}, nil
	case ProfileContainer:
		if !evidence.ContainerReady() {
			return Selection{}, errors.New("container sandbox backend evidence missing")
		}
		return Selection{
			Profile:       ProfileContainer,
			Backend:       ProfileContainer,
			WritablePaths: normalizeWritablePaths(writablePaths),
			NetworkEgress: "deny",
		}, nil
	default:
		return Selection{}, errors.New("sandbox backend unavailable")
	}
}

func (e Evidence) ContainerReady() bool {
	return e.ContainerBackendReady && e.Rootless && e.ReadOnlyFS && e.NoNewPrivileges && e.NetworkDefaultDeny
}

func requiredProfile(obligations map[string]any) string {
	value, ok := obligations["sandbox_mode"]
	if !ok {
		return ProfileNone
	}
	switch v := value.(type) {
	case string:
		return NormalizeProfile(v)
	case []any:
		options := make([]string, 0)
		for _, entry := range v {
			if s, ok := entry.(string); ok {
				options = append(options, NormalizeProfile(s))
			}
		}
		sort.Slice(options, func(i, j int) bool {
			return profileOrder[options[i]] > profileOrder[options[j]]
		})
		if len(options) > 0 {
			return options[0]
		}
	}
	return ProfileNone
}

func normalizeWritablePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if trimmed := strings.TrimSpace(path); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

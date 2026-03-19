package sandbox

import "testing"

func TestSelectProfile(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": "container",
	}
	_, err := SelectProfile(obligations, "local")
	if err == nil {
		t.Fatal("expected container requirement to fail with local profile")
	}
	profile, err := SelectProfile(obligations, "container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile != "container" {
		t.Fatalf("expected container, got %s", profile)
	}
}

func TestSelectProfileList(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": []any{"local", "container"},
	}
	profile, err := SelectProfile(obligations, "container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile != "container" {
		t.Fatalf("expected container, got %s", profile)
	}
}

func TestSelectBackendFailsClosedWithoutContainerEvidence(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": "container",
	}
	_, err := SelectBackend(obligations, "container", Evidence{}, []string{"C:\\workspace"})
	if err == nil {
		t.Fatal("expected missing container evidence to fail closed")
	}
}

func TestSelectBackendContainerProvidesWritablePathsAndDefaultDenyEgress(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": "container",
	}
	selection, err := SelectBackend(obligations, "container", Evidence{
		ContainerBackendReady: true,
		Rootless:              true,
		ReadOnlyFS:            true,
		NoNewPrivileges:       true,
		NetworkDefaultDeny:    true,
	}, []string{"C:\\workspace"})
	if err != nil {
		t.Fatalf("unexpected backend selection error: %v", err)
	}
	if selection.Profile != ProfileContainer || selection.Backend != ProfileContainer {
		t.Fatalf("expected container backend selection, got %+v", selection)
	}
	if selection.NetworkEgress != "deny" {
		t.Fatalf("expected deny-by-default egress, got %+v", selection)
	}
	if len(selection.WritablePaths) != 1 || selection.WritablePaths[0] != "C:\\workspace" {
		t.Fatalf("expected explicit writable path list, got %+v", selection.WritablePaths)
	}
}

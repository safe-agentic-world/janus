package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

type reloadRecordSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *reloadRecordSink) WriteEvent(event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func TestReloadSetPolicyEngineSwapsAtomicallyDuringActions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	allowEngine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Hash:    "allow-bundle",
		Rules: []policy.Rule{{
			ID:         "allow-read",
			ActionType: "fs.read",
			Resource:   "file://workspace/README.md",
			Decision:   policy.DecisionAllow,
		}},
	})
	denyEngine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Hash:    "deny-bundle",
		Rules: []policy.Rule{{
			ID:         "deny-read",
			ActionType: "fs.read",
			Resource:   "file://workspace/README.md",
			Decision:   policy.DecisionDeny,
		}},
	})
	svc := New(
		allowEngine,
		executor.NewFSReader(dir, 1024, 20),
		executor.NewFSWriter(dir, 1024),
		executor.NewPatchApplier(dir, 1024),
		executor.NewExecRunner(dir, 1024),
		executor.NewHTTPRunner(1024),
		&reloadRecordSink{},
		redact.DefaultRedactor(),
		nil,
		nil,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "reload-read",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "reload-read",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("action: %v", err)
	}

	stop := make(chan struct{})
	started := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, _, err := svc.EvaluateAction(act); err != nil {
					t.Errorf("evaluate during reload: %v", err)
					return
				}
				if _, err := svc.Process(act); err != nil {
					t.Errorf("process during reload: %v", err)
					return
				}
				if first {
					started <- struct{}{}
					first = false
				}
			}
		}()
	}
	for i := 0; i < cap(started); i++ {
		<-started
	}

	if err := svc.SetPolicyEngine(denyEngine); err != nil {
		t.Fatalf("swap policy: %v", err)
	}
	close(stop)
	wg.Wait()

	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process after reload: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny after reload, got %+v", resp)
	}
}

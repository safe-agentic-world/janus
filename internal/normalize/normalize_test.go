package normalize

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
)

func TestNormalizeFileTraversalRejected(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/dir/../secret.txt",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestNormalizeRejectsSymlinkEscapeLikeTraversal(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/link/../outside",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected symlink escape rejection")
	}
}

func TestNormalizeEquivalentURIs(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace//a/b",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "file://workspace/a/b" {
		t.Fatalf("expected normalized resource, got %s", result.Resource)
	}
}

func TestNormalizeURLHostLowercase(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "net.http_request",
		Resource:      "url://Example.COM:80/path",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "url://example.com/path" {
		t.Fatalf("expected normalized url, got %s", result.Resource)
	}
}

func TestNormalizeRepoLowercase(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "repo.apply_patch",
		Resource:      "repo://Org/Service",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if result.Resource != "repo://org/service" {
		t.Fatalf("expected normalized repo, got %s", result.Resource)
	}
}

func TestNormalizeCustomResource(t *testing.T) {
	result, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "payments.refund",
		Resource:      "Payment://Shop.Example.Com/orders/ORD-1001",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err != nil {
		t.Fatalf("normalize custom resource: %v", err)
	}
	if result.Resource != "payment://shop.example.com/orders/ORD-1001" {
		t.Fatalf("expected normalized custom resource, got %s", result.Resource)
	}
}

func TestNormalizeCustomResourceRejectsQuery(t *testing.T) {
	_, err := Action(action.Action{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "payments.refund",
		Resource:      "payment://shop.example.com/orders/ORD-1001?x=1",
		Params:        []byte(`{}`),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
		Context:       action.Context{},
	})
	if err == nil {
		t.Fatal("expected custom resource query rejection")
	}
}

func TestMatchPatternDeterministic(t *testing.T) {
	ok, err := MatchPattern("foo/*/bar", "foo/a/bar")
	if err != nil {
		t.Fatalf("match error: %v", err)
	}
	if !ok {
		t.Fatal("expected match")
	}
	_, err = MatchPattern("foo\\*\\bar", "foo\\a\\bar")
	if err == nil {
		t.Fatal("expected backslash error")
	}
}

func TestNormalizationIsPure(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "normalize.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if path == "os" || path == "path/filepath" {
			t.Fatalf("normalize imports forbidden package %s", path)
		}
	}
}

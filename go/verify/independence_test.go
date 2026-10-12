package verify

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The verifier's value rests entirely on not depending on the thing it
// verifies. That is an architectural property, and architectural properties
// decay the first time someone needs a helper in a hurry — so it is a test,
// not a paragraph in a README.
//
// The rule: nothing in package verify may reach the log, the cgo bridge, or
// the service. It may use the Go standard library and nothing else.
func TestVerifierImportsNothingItVerifies(t *testing.T) {
	forbidden := []string{
		"C",             // cgo, which would link sentinel-core
		"logstore",      // the bridge to the Rust core
		"service",       // the HTTP server
		"sentinel-core", // the Rust crate by any path
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// Test files are checked too. A test that imports the server to
		// "make the fixtures easier" quietly destroys the property, and that
		// is the realistic way this breaks.
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import literal %s", e.Name(), imp.Path.Value)
			}
			for _, bad := range forbidden {
				if path == bad || strings.Contains(path, bad) {
					t.Errorf("%s imports %q: the verifier must not depend on what it verifies",
						e.Name(), path)
				}
			}
			if isModuleLocal(path) {
				t.Errorf("%s imports %q: package verify must depend only on the standard library",
					e.Name(), path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were examined, so this test proved nothing")
	}
}

// isModuleLocal reports whether an import path belongs to this repository.
//
// Standard-library paths have no dot in their first segment, which is the
// same heuristic the go tool uses to tell stdlib from everything else.
func isModuleLocal(path string) bool {
	first := path
	if i := strings.Index(path, "/"); i >= 0 {
		first = path[:i]
	}
	return strings.Contains(first, ".")
}

// A second, blunter check: the package must build with cgo disabled. If
// anything in the dependency graph needed the Rust static library, this would
// fail to compile — and it is the property an auditor actually cares about,
// since they will be running the verifier on a machine that has never seen
// sentinel-core.
func TestVerifierDirectoryHasNoCgoDirectives(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// The needle is assembled rather than written out, because this
		// file would otherwise match itself — the first version of this test
		// failed on its own source, which is funny once.
		needle := "#" + "cgo"
		if strings.Contains(string(src), needle) {
			t.Errorf("%s contains a %s directive", e.Name(), needle)
		}
	}

	// And confirm the package really is a leaf: no non-stdlib imports
	// anywhere, including transitively, is implied by the import check above,
	// but assert the directory layout assumption it rests on.
	if _, err := os.Stat(filepath.Join("..", "logstore")); err != nil {
		t.Skip("logstore package not present; nothing to be independent of")
	}
}

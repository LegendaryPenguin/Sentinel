package audit

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// An auditor runs on a machine that has never seen sentinel-core and cannot
// link it. If this package acquired a dependency on logstore it would become
// unbuildable in exactly the place it is needed, so the constraint is a test
// rather than a convention.
func TestAuditorDoesNotLinkTheLog(t *testing.T) {
	forbidden := []string{"C", "logstore", "service", "sentinel-core"}

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
					t.Errorf("%s imports %q: an auditor must not link what it audits", e.Name(), path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were examined, so this test proved nothing")
	}
}

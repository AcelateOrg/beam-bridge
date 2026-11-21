package coreapi_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEngineReachableOnlyViaCoreAPI enforces the core-isolation rule: the Xray
// engine (github.com/xtls/xray-core) may be imported only by the core/xray
// adapter and the cmd/xrayprobe diagnostic tool. Every other bridge package must
// reach the core through the coreapi seam, so replacing or migrating the engine
// never leaks into the rest of the codebase.
func TestEngineReachableOnlyViaCoreAPI(t *testing.T) {
	root := moduleRoot(t)

	allowed := []string{
		filepath.Join("core", "xray"),
		filepath.Join("cmd", "xrayprobe"),
	}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		for _, a := range allowed {
			if rel == a || strings.HasPrefix(rel, a+string(filepath.Separator)) {
				return nil
			}
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, "\"")
			if strings.HasPrefix(p, "github.com/xtls/xray-core") {
				t.Errorf("%s imports engine package %q; the core must be reached via coreapi", rel, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

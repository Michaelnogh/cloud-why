package main

import (
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests prove the offline boundary structurally (spec P06, P07):
// the evaluation packages cannot open files or sockets because they do not
// import any package that can, and the whole binary links no networking
// package except net/url (string decoding only).

const module = "github.com/Michaelnogh/cloud-why"

var moduleRoot = filepath.Join("..", "..")

// pureDirs are the packages that must not perform I/O.
var pureDirs = []string{
	"internal/investigation",
	"internal/providers/aws/snapshot",
	"internal/providers/aws/engine",
}

func forbiddenDirect(pkg, imp string) bool {
	switch {
	case imp == "net/url":
		return pkg != "internal/providers/aws/snapshot"
	case imp == "net", strings.HasPrefix(imp, "net/"):
		return true
	}
	return slices.Contains([]string{"os", "os/exec", "crypto/tls", "plugin", "syscall", "unsafe"}, imp)
}

// P06: direct imports of every package.
func TestDirectImports(t *testing.T) {
	dirs := append([]string{"cmd/cloud-why", "internal/render"}, pureDirs...)
	for _, dir := range dirs {
		p, err := build.Default.ImportDir(filepath.Join(moduleRoot, dir), 0)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, module+"/") {
				if dir == "internal/investigation" {
					t.Errorf("%s must not import module packages, imports %s", dir, imp)
				}
				continue
			}
			if strings.Contains(strings.Split(imp, "/")[0], ".") {
				t.Errorf("%s imports non-standard package %s", dir, imp)
			}
			if slices.Contains(pureDirs, dir) && forbiddenDirect(dir, imp) {
				t.Errorf("%s must not import %s", dir, imp)
			}
			if dir == "internal/render" && (imp == "os" || imp == "net" || strings.HasPrefix(imp, "net/")) {
				t.Errorf("%s must not import %s", dir, imp)
			}
		}
	}
}

// P06: transitive dependencies of the whole binary, as resolved by the go
// tool. No networking, TLS, process execution or third-party code.
func TestTransitiveDependencies(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}NONSTD {{end}}{{.ImportPath}}", "./cmd/cloud-why")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(strings.ReplaceAll(string(out), "NONSTD ", "NONSTD:"))
	if len(deps) == 0 {
		t.Fatal("no dependencies listed")
	}
	for _, d := range deps {
		if rest, ok := strings.CutPrefix(d, "NONSTD:"); ok {
			if !strings.HasPrefix(rest, module) {
				t.Errorf("third-party dependency %s", rest)
			}
			continue
		}
		switch {
		// net/url (string decoding) and its dependency net/netip (IP
		// address value types) perform no I/O; TestNetURLHasNoIO checks it.
		case d == "net/url", d == "net/netip":
		case d == "net", strings.HasPrefix(d, "net/"), strings.Contains(d, "golang.org/x/net"),
			d == "crypto/tls", d == "os/exec", d == "plugin":
			t.Errorf("binary depends on %s", d)
		case strings.Contains(d, "aws-sdk") || strings.Contains(d, "github.com/aws"):
			t.Errorf("AWS SDK in dependency graph: %s", d)
		}
	}
}

// The only networking-named packages in the binary, net/url and net/netip,
// do no I/O themselves: they import no os, syscall, net or poller package.
// (net/url imports fmt, which uses os only for Print* to standard streams.)
func TestNetURLHasNoIO(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \" \"}}", "net/url", "net/netip")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, d := range strings.Fields(string(out)) {
		if d == "os" || d == "syscall" || d == "net" || d == "internal/poll" || strings.HasPrefix(d, "internal/syscall") {
			t.Errorf("net/url or net/netip imports %s", d)
		}
	}
}

// P07: go.mod has no requirements.
func TestNoModuleRequirements(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require") {
			t.Errorf("go.mod contains a require directive: %q", line)
		}
	}
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.sum")); err == nil {
		t.Errorf("go.sum exists; CW-001 has no module dependencies")
	}
}

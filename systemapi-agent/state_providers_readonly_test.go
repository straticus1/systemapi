package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The read-only guarantee of Check is structural. These tests pin it.

// TestReadOnlyHostMethodSet: ReadOnlyHost exposes only reads, and neither it
// nor the real read backend implements a write interface.
func TestReadOnlyHostMethodSet(t *testing.T) {
	allowed := map[string]bool{"Stat": true, "ReadFile": true, "Package": true, "Service": true, "Sysctl": true}
	rt := reflect.TypeOf(ReadOnlyHost{})
	for i := 0; i < rt.NumMethod(); i++ {
		if name := rt.Method(i).Name; !allowed[name] {
			t.Errorf("ReadOnlyHost has method %s", name)
		}
	}
	if rt.Kind() != reflect.Struct {
		t.Fatal("ReadOnlyHost must be a struct, so it cannot be type-asserted")
	}
	writes := reflect.TypeOf((*hostWrites)(nil)).Elem()
	for _, typ := range []reflect.Type{rt, reflect.TypeOf(osHostReads{}), reflect.TypeOf(&osHostReads{})} {
		if typ.Implements(writes) {
			t.Errorf("%v implements hostWrites", typ)
		}
	}
	readNames := map[string]bool{"stat": true, "readFile": true, "packageQuery": true, "serviceState": true, "sysctlGet": true}
	reads := reflect.TypeOf((*hostReads)(nil)).Elem()
	for i := 0; i < reads.NumMethod(); i++ {
		if name := reads.Method(i).Name; !readNames[name] {
			t.Errorf("hostReads has method %s", name)
		}
	}
	for i := 0; i < reflect.TypeOf(osHostReads{}).NumMethod(); i++ {
		t.Errorf("osHostReads exports method %s", reflect.TypeOf(osHostReads{}).Method(i).Name)
	}
}

// writeIdents may not appear in a Check body or in a same-file function a
// Check body calls.
var writeIdents = map[string]bool{
	"WriteHost": true, "hostWrites": true, "newWriteHost": true, "newWrites": true, "osHostWrites": true,
	"w": true, "Apply": true, "applyChecked": true,
	"ReplaceFile": true, "Mkdir": true, "Chmod": true, "Chown": true, "Remove": true,
	"writeBeneath": true, "replaceBeneath": true, "atomicReplace": true, "atomicReplaceMode": true,
	"mkdirBeneath": true, "chmodBeneath": true, "chownBeneath": true, "removeBeneath": true,
	"backupOutside": true, "backup": true, "changePackage": true, "installPackage": true,
	"Action": true, "SysctlSet": true, "hostSysctlSet": true, "sysctlSet": true, "serviceAction": true,
	"packageChange": true, "replaceFile": true, "mkdirAll": true, "chmod": true, "chown": true, "remove": true,
	"RemoveAll": true, "WriteFile": true, "MkdirAll": true, "Rename": true, "Create": true, "OpenFile": true,
	"Symlink": true, "Link": true, "Truncate": true, "jobCommand": true, "currentPlatform": true,
}

func TestCheckBodiesNameNoWriteHelper(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "state_providers.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	var checks []*ast.FuncDecl
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Recv == nil {
			funcs[fd.Name.Name] = fd
		} else if fd.Name.Name == "Check" {
			checks = append(checks, fd)
		}
	}
	if len(checks) != 6 {
		t.Fatalf("found %d Check methods, want 6", len(checks))
	}
	seen := map[*ast.FuncDecl]bool{}
	var scan func(fd *ast.FuncDecl, from string)
	scan = func(fd *ast.FuncDecl, from string) {
		if seen[fd] {
			return
		}
		seen[fd] = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if writeIdents[id.Name] {
				t.Errorf("%s: %s names %s", fset.Position(id.Pos()), from, id.Name)
			}
			if callee, ok := funcs[id.Name]; ok {
				scan(callee, from+" -> "+id.Name)
			}
			return true
		})
	}
	for _, fd := range checks {
		recv := fd.Recv.List[0].Type.(*ast.StarExpr).X.(*ast.Ident).Name
		if fd.Type.Params.List[1].Type.(*ast.Ident).Name != "ReadOnlyHost" {
			t.Errorf("%s.Check does not take a ReadOnlyHost", recv)
		}
		scan(fd, recv+".Check")
	}
}

// TestCheckerCannotReachWriteHostCompileTime builds the package with an
// extra file that tries to turn a Checker's view into a write view. Each
// attempt must be a compile error.
func TestCheckerCannotReachWriteHostCompileTime(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not found: %v", err)
	}
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"assert ReadOnlyHost to WriteHost":  `func _(ro ReadOnlyHost) { _, _ = ro.(WriteHost) }`,
		"convert ReadOnlyHost to WriteHost": `func _(ro ReadOnlyHost) { _ = WriteHost(ro) }`,
		"use the read backend as writes":    `var _ hostWrites = osHostReads{}`,
	}
	want := map[string]string{
		"assert ReadOnlyHost to WriteHost":  "not an interface",
		"convert ReadOnlyHost to WriteHost": "cannot convert",
		"use the read backend as writes":    "does not implement hostWrites",
	}
	tmp := t.TempDir()
	for name, body := range cases {
		src := filepath.Join(tmp, "zz_readonly_probe.go")
		if err := os.WriteFile(src, []byte("package main\n\n"+body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		overlay, err := json.Marshal(map[string]map[string]string{
			"Replace": {filepath.Join(pkgDir, "zz_readonly_probe.go"): src},
		})
		if err != nil {
			t.Fatal(err)
		}
		ov := filepath.Join(tmp, "overlay.json")
		if err := os.WriteFile(ov, overlay, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(goBin, "build", "-overlay="+ov, "-o", os.DevNull, ".")
		cmd.Dir = pkgDir
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: compiled", name)
			continue
		}
		if !strings.Contains(string(out), "zz_readonly_probe.go") || !strings.Contains(string(out), want[name]) {
			t.Errorf("%s: unexpected build failure:\n%s", name, out)
		}
	}
}

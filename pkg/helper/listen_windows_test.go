//go:build windows

package helper

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privileged enables what setting a file's owner to SYSTEM takes when the
// test is not SYSTEM itself (the helper is): SeRestorePrivilege, which an
// elevated administrator holds disabled. A test run without it is skipped,
// not passed.
func privileged(t *testing.T) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Skipf("open token: %v", err)
	}
	defer tok.Close()
	for _, name := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			t.Skipf("%s: %v", name, err)
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil); err != nil {
			t.Skipf("enable %s: %v", name, err)
		}
		// AdjustTokenPrivileges succeeds without granting a privilege the
		// token does not hold, and says so only through the last error.
		if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
			t.Skipf("%s is not held: run the tests elevated", name)
		}
	}
}

// shortDir is a temporary directory with a short path: an AF_UNIX socket's
// path must fit in 108 bytes, and t.TempDir's carries the test's name.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func setSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	if err := applySDDL(path, sddl); err != nil {
		t.Fatalf("set %s on %s: %v", sddl, path, err)
	}
}

// The directory and the socket come out as dirSDDL and socketSDDL said,
// read back from the file system, and the socket answers.
func TestListenSecuresTheDirectoryAndTheSocket(t *testing.T) {
	privileged(t)
	dir := filepath.Join(shortDir(t), "Claimward")
	sock := filepath.Join(dir, "helper.sock")
	ln, err := Listen(sock, "Users")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := checkPath(dir); err != nil {
		t.Errorf("the directory does not pass the check: %v", err)
	}
	users, _, _, err := windows.LookupSID("", "Users")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{dir: dirSDDL(users.String()), sock: socketSDDL(users.String())} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		got := sd.String()
		if !strings.HasPrefix(got, "O:SY") || !strings.Contains(got, "D:P") || !strings.Contains(got, users.String()) {
			t.Errorf("%s: %s, want the shape of %s", path, got, want)
		}
	}
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("an administrator cannot reach the socket: %v", err)
	}
	c.Close()
}

// An existing directory with ProgramData's loose ACL is tightened.
func TestListenTightensAnExistingDirectory(t *testing.T) {
	privileged(t)
	dir := filepath.Join(shortDir(t), "Claimward")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, dir, "O:BUG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	if err := checkPath(dir); err == nil {
		t.Fatal("the loose directory passes the check before Listen")
	}
	ln, err := Listen(filepath.Join(dir, "helper.sock"), "")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if err := checkPath(dir); err != nil {
		t.Errorf("after Listen: %v", err)
	}
}

// A junction where the directory should be is refused.
func TestListenRefusesAJunction(t *testing.T) {
	privileged(t)
	base := shortDir(t)
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "Claimward")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink: %v: %s", err, out)
	}
	if ln, err := Listen(filepath.Join(link, "helper.sock"), ""); err == nil {
		ln.Close()
		t.Fatal("the socket was put behind a junction")
	}
}

// helper.json must be SYSTEM's or the Administrators', and theirs alone to
// write.
func TestTheConfigurationIsTheAdministratorsAlone(t *testing.T) {
	privileged(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "helper.json")
	if err := os.WriteFile(p, []byte(`{"servers": ["https://vpn.example.org"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, p, "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("a good configuration: %v", err)
	}
	if cfg.Group != DefaultGroup || cfg.Group != "Claimward Users" {
		t.Errorf("group %q, want the default %q", cfg.Group, "Claimward Users")
	}

	setSDDL(t, p, "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	if _, err := LoadConfig(p); err == nil {
		t.Error("a configuration Users may write was taken")
	}
	setSDDL(t, p, "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;IU)")
	if _, err := LoadConfig(p); err == nil {
		t.Error("a configuration interactive users may write was taken")
	}
	setSDDL(t, p, "O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if _, err := LoadConfig(p); err == nil {
		t.Error("a configuration Users own was taken")
	}
}

func TestSocketGroup(t *testing.T) {
	if sid, err := socketGroup(""); err != nil || sid != sidInteractive {
		t.Errorf(`socketGroup("") = %s %v, want INTERACTIVE`, sid, err)
	}
	if sid, err := socketGroup("no such group, surely"); err != nil || sid != sidInteractive {
		t.Errorf("a missing group = %s %v, want the INTERACTIVE fallback", sid, err)
	}
	if sid, err := socketGroup("Administrators"); err != nil || sid != sidAdministrators {
		t.Errorf("Administrators = %s %v", sid, err)
	}
	if u := os.Getenv("USERNAME"); u != "" {
		if _, err := socketGroup(u); err == nil {
			t.Errorf("a user account %q was taken as a group", u)
		}
	}
}

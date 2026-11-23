//go:build windows

package helper

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Audit 2026-11-23, finding 2: C:\ProgramData lets every user create a
// directory, which that user then owns. When the helper's directory already
// exists, createSecured keeps it, and applySDDL replaces its owner and DACL --
// but a handle its creator opened beforehand with WRITE_DAC keeps that right
// (Windows checks access when a handle is opened, never after), so the
// creator can grant themselves the directory back once checkPath has passed,
// delete the helper's socket and listen in its place. A directory the helper
// did not create, owned by anybody but SYSTEM or the Administrators, must be
// refused (or renamed away and created afresh), never adopted.
//
// Run elevated: Listen sets the owner to the Administrators.
func TestListenRefusesADirectorySomebodyElseCreated(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process (Listen sets the owner to BUILTIN\\Administrators)")
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tu.User.Sid.String()

	// The "attacker" creates the directory first and owns it.
	dir := filepath.Join(t.TempDir(), "Claimward")
	sd, err := windows.SecurityDescriptorFromString("O:" + me + "D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil {
		t.Fatal(err)
	}
	// ... and keeps a handle with WRITE_DAC open.
	h, err := windows.CreateFile(p, windows.WRITE_DAC|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	ln, err := Listen(filepath.Join(dir, "helper.sock"), "")
	if err != nil {
		t.Logf("refused: %v", err)
		return
	}
	defer ln.Close()

	// Through the retained handle, the directory is the attacker's again.
	everyone, _ := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	dacl, _, _ := everyone.DACL()
	regrant := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	t.Fatalf("Listen adopted a directory owned by %s; re-granting it through the handle kept from before: %v; checkPath now: %v",
		me, regrant, checkPath(dir))
}

//go:build windows

package helper

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultGroup is the local group allowed to use the socket beside SYSTEM
// and the Administrators: "Claimward Users", which the installer creates.
// When it does not exist the socket is opened to INTERACTIVE, whoever is
// logged on at the machine -- see socketGroup.
var DefaultGroup = windowsDefaultGroup

// Listen opens the helper's AF_UNIX socket (Windows 10 1803 and later).
// Who may reach it is decided by ACLs, set here rather than left to the
// installer:
//
//   - the directory gets a protected DACL (dirSDDL): SYSTEM and
//     Administrators in full control, the group allowed to list and
//     traverse it. Nothing is inherited from ProgramData, which lets every
//     user create files there; without this a user could create the
//     directory first, or a file in it, and own it.
//   - the socket gets its own (socketSDDL): the group may connect.
//
// ⛔ A directory that is a reparse point (a junction or a symbolic link) is
// refused: whoever planted it chose where the ACL and the socket land.
func Listen(path, group string) (net.Listener, error) {
	sid, err := socketGroup(group)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := createSecured(dir, dirSDDL(sid)); err != nil {
		return nil, err
	}
	if err := refuseReparsePoint(dir); err != nil {
		return nil, err
	}
	if err := applySDDL(dir, dirSDDL(sid)); err != nil {
		return nil, fmt.Errorf("secure %s: %w", dir, err)
	}
	// Read back: an ACL that was asked for is not one that holds.
	if err := checkPath(dir); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := applySDDL(path, socketSDDL(sid)); err != nil {
		ln.Close()
		return nil, fmt.Errorf("secure %s: %w", path, err)
	}
	return ln, nil
}

// socketGroup is the SID of the group allowed on the socket: the named
// local group, or INTERACTIVE when it does not exist (logged, since it is
// wider: every person logged on at the machine, rather than those an
// administrator added). An empty name asks for INTERACTIVE outright.
func socketGroup(group string) (string, error) {
	if group == "" {
		return sidInteractive, nil
	}
	sid, _, typ, err := windows.LookupSID("", group)
	if err != nil {
		slog.Warn("the helper's group does not exist; the socket is open to every interactive user",
			"group", group, "err", err)
		return sidInteractive, nil
	}
	if typ != windows.SidTypeAlias && typ != windows.SidTypeGroup && typ != windows.SidTypeWellKnownGroup {
		return "", fmt.Errorf("%q is not a group (SID type %d)", group, typ)
	}
	return sid.String(), nil
}

// createSecured creates dir already carrying sddl, when it does not exist:
// created bare and secured after, it would for a moment inherit
// ProgramData's ACL, under which any user may create a file in it, and keep
// a handle opened in that moment.
func createSecured(dir, sddl string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}

// applySDDL sets the owner and a protected DACL on a file or directory.
func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

func refuseReparsePoint(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point (junction or link); refusing to put the helper's socket where it leads", path)
	}
	return nil
}

// checkOwner refuses a configuration file anybody but SYSTEM or the
// Administrators owns or may write: whoever writes it chooses the server
// the helper trusts. The installer creates it with the directory's
// inherited ACL (SYSTEM and Administrators only).
func checkOwner(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err := refuseReparsePoint(path); err != nil {
		return err
	}
	return checkPath(path)
}

// checkPath reads a file's or directory's owner and DACL and hands them to
// checkACL.
func checkPath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("it has no owner")
	}
	var aces []ace
	if dacl != nil {
		for i := 0; i < int(dacl.AceCount); i++ {
			var a *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, uint32(i), &a); err != nil {
				return err
			}
			// Every ACE a DACL holds starts with this header and mask,
			// and the plain ones (allow and deny) then carry the SID.
			// An object or callback ACE carries more before its SID; it
			// is recorded with the SID of the plain layout's position,
			// which is not its trustee -- and so is never "trusted",
			// which is what checkACL needs to refuse it.
			sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
			s := "unparsed"
			if a.Header.AceType == 0x0 || a.Header.AceType == 0x1 {
				s = sid.String()
			}
			aces = append(aces, ace{Type: a.Header.AceType, Flags: a.Header.AceFlags, Mask: uint32(a.Mask), SID: s})
		}
	}
	return checkACL(owner.String(), aces, dacl == nil)
}

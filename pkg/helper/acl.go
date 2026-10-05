package helper

// The Windows access rules, as pure functions: what DACL the helper puts on
// its socket's directory and on the socket, and what it accepts on its
// configuration file. listen_windows.go applies and reads them through the
// Win32 security API; they live here, untagged, so that they are tested on
// every platform rather than only on a Windows machine nobody's CI has.

import (
	"fmt"
	"strings"
)

// Well-known SIDs.
const (
	sidSystem         = "S-1-5-18"     // NT AUTHORITY\SYSTEM, the helper's own account
	sidAdministrators = "S-1-5-32-544" // BUILTIN\Administrators
	// sidInteractive is NT AUTHORITY\INTERACTIVE: whoever is logged on at
	// the machine (console or Remote Desktop), the fallback when the
	// "Claimward Users" group does not exist.
	sidInteractive = "S-1-5-4"
)

// windowsDefaultGroup is the local group allowed to use the socket. The
// installer (scripts/install.ps1 in the app) creates it and adds the person;
// a helper that finds no such group falls back to sidInteractive.
const windowsDefaultGroup = "Claimward Users"

// Access rights, from winnt.h.
const (
	fileListDirectory = 0x0001 // FILE_READ_DATA on a file
	fileAddFile       = 0x0002 // FILE_WRITE_DATA on a file
	fileAddSubdir     = 0x0004 // FILE_APPEND_DATA on a file
	fileReadEA        = 0x0008
	fileTraverse      = 0x0020 // FILE_EXECUTE on a file
	fileDeleteChild   = 0x0040
	fileReadAttrs     = 0x0080
	fileWriteAttrs    = 0x0100
	fileWriteEA       = 0x0010
	accessDelete      = 0x00010000
	readControl       = 0x00020000
	writeDAC          = 0x00040000
	writeOwner        = 0x00080000
	synchronize       = 0x00100000
	genericAll        = 0x10000000
	genericWrite      = 0x40000000

	// dirUse is what the socket's group gets on the directory: list and
	// traverse it, nothing more (FILE_GENERIC_READ | FILE_TRAVERSE).
	dirUse = synchronize | readControl | fileReadAttrs | fileTraverse | fileReadEA | fileListDirectory
	// socketUse is what it gets on the socket: read and write, which is
	// what connecting to an AF_UNIX socket takes -- the 0660 of the Unix
	// helper (FILE_GENERIC_READ | FILE_GENERIC_WRITE).
	socketUse = synchronize | readControl | fileReadAttrs | fileReadEA | fileListDirectory |
		fileWriteAttrs | fileWriteEA | fileAddSubdir | fileAddFile

	// writeRights are the rights that let somebody change what a file
	// says, replace it, or give themselves the right to: whoever holds one
	// on helper.json chooses the server the helper trusts. On a directory
	// the same bits are add-file, add-subdirectory and delete-child.
	writeRights = fileAddFile | fileAddSubdir | fileDeleteChild | accessDelete |
		writeDAC | writeOwner | genericWrite | genericAll
)

// ACE types and flags, from winnt.h.
const (
	aceAllowed     = 0x0
	aceInheritOnly = 0x08
)

// denies are the ACE types that take rights away (plain, object, callback
// and callback-object). Every other type a DACL may hold grants them, and
// is counted as granting: an allow that arrives as an object or callback
// ACE is still an allow.
var denies = map[byte]bool{0x1: true, 0x6: true, 0xA: true, 0xC: true}

// ace is one access-control entry, reduced to what the check reads.
type ace struct {
	Type  byte   // aceAllowed, a deny (see denies), ...
	Flags byte   // aceInheritOnly, ...
	Mask  uint32 // access rights
	SID   string // the trustee, in S-1-... form
}

// trusted is whoever may write the helper's files: the helper's account
// and the administrators, who installed it.
func trusted(sid string) bool { return sid == sidSystem || sid == sidAdministrators }

// dirSDDL is the security descriptor of the socket's directory: owned by
// SYSTEM; SYSTEM and Administrators in full control of it and of everything
// created in it (inherited); the group allowed to list and traverse it and
// nothing else, so that it can reach the socket but neither create a file
// beside it nor replace it.
//
// "P" protects the DACL: nothing is inherited from ProgramData, whose own
// ACL lets every user create files and folders.
func dirSDDL(groupSID string) string {
	return fmt.Sprintf("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x%x;;;%s)", dirUse, groupSID)
}

// socketSDDL is the socket's: SYSTEM and Administrators in full control,
// the group allowed to connect. It is set on the socket right after it is
// created; until then the socket carries only what the directory passes
// down, SYSTEM and Administrators, so there is no moment at which it is
// open wider than this.
func socketSDDL(groupSID string) string {
	return fmt.Sprintf("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x%x;;;%s)", socketUse, groupSID)
}

// checkACL refuses a file, or a directory, that somebody other than SYSTEM
// or the Administrators owns or may write. A nil DACL (dacl == nil, not an
// empty one) grants everybody everything.
//
// Deny entries are not counted in anybody's favour: a deny for one user
// says nothing about the others, and reasoning about which entry wins is
// how an ACL check gets talked out of its answer. Inherit-only entries do
// not apply to the object itself, only to what is created in it.
func checkACL(owner string, dacl []ace, nilDACL bool) error {
	if !trusted(owner) {
		return fmt.Errorf("owned by %s, not by SYSTEM or Administrators", owner)
	}
	if nilDACL {
		return fmt.Errorf("it has no DACL: everybody may write it")
	}
	var writers []string
	for _, a := range dacl {
		if denies[a.Type] || a.Flags&aceInheritOnly != 0 {
			continue
		}
		if a.Mask&writeRights != 0 && !trusted(a.SID) {
			writers = append(writers, fmt.Sprintf("%s (0x%x)", a.SID, a.Mask))
		}
	}
	if len(writers) > 0 {
		return fmt.Errorf("writable by somebody other than SYSTEM or Administrators: %s", strings.Join(writers, ", "))
	}
	return nil
}

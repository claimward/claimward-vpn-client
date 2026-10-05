package helper

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// parseSDDL reads the owner and the DACL out of the SDDL this package
// writes, so the descriptor it APPLIES can be put through the check it
// ENFORCES -- on any platform. It knows the few aliases used here and
// in ProgramData's default descriptor, which is all it is for.
func parseSDDL(t *testing.T, sddl string) (owner string, dacl []ace, protected bool) {
	t.Helper()
	alias := map[string]string{"SY": sidSystem, "BA": sidAdministrators, "BU": "S-1-5-32-545",
		"CO": "S-1-3-0", "IU": sidInteractive, "WD": "S-1-1-0", "AU": "S-1-5-11"}
	rights := map[string]uint32{"FA": 0x1f01ff, "GA": genericAll, "GW": genericWrite, "GR": 0x80000000, "GX": 0x20000000,
		"FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0, "WD": writeDAC, "WO": writeOwner,
		"DC": fileDeleteChild, "WP": fileAddSubdir, "CC": fileListDirectory, "LC": fileAddFile}
	sid := func(s string) string {
		if a, ok := alias[s]; ok {
			return a
		}
		return s
	}
	m := regexp.MustCompile(`^O:([^G]+)G:[^D]+D:(P?)(.*)$`).FindStringSubmatch(sddl)
	if m == nil {
		t.Fatalf("unparsed SDDL %q", sddl)
	}
	owner, protected = sid(m[1]), m[2] == "P"
	for _, e := range regexp.MustCompile(`\(([^)]*)\)`).FindAllStringSubmatch(m[3], -1) {
		f := strings.Split(e[1], ";")
		if len(f) != 6 {
			t.Fatalf("unparsed ACE %q", e[1])
		}
		var a ace
		switch f[0] {
		case "A":
			a.Type = aceAllowed
		case "D":
			a.Type = 0x1
		default:
			t.Fatalf("unknown ACE type %q", f[0])
		}
		if strings.Contains(f[1], "IO") {
			a.Flags |= aceInheritOnly
		}
		if strings.HasPrefix(f[2], "0x") {
			v, err := strconv.ParseUint(f[2][2:], 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			a.Mask = uint32(v)
		} else {
			for i := 0; i+2 <= len(f[2]); i += 2 {
				r, ok := rights[f[2][i:i+2]]
				if !ok {
					t.Fatalf("unknown right %q in %q", f[2][i:i+2], e[1])
				}
				a.Mask |= r
			}
		}
		a.SID = sid(f[5])
		dacl = append(dacl, a)
	}
	return owner, dacl, protected
}

const someGroup = "S-1-5-21-1111111111-2222222222-3333333333-1001"

// The directory and the socket the helper creates are protected from
// ProgramData's inheritance, are SYSTEM's, and give the group what it needs
// and no more; the directory passes the check the helper applies to it.
func TestTheHelpersOwnDescriptorsPassItsCheck(t *testing.T) {
	for name, sddl := range map[string]string{"directory": dirSDDL(someGroup), "socket": socketSDDL(someGroup)} {
		owner, dacl, protected := parseSDDL(t, sddl)
		if !protected {
			t.Errorf("%s: the DACL is not protected; it would inherit ProgramData's", name)
		}
		if owner != sidSystem {
			t.Errorf("%s: owned by %s, want SYSTEM", name, owner)
		}
		// The directory holds helper.json beside the socket: nobody but
		// SYSTEM and Administrators may add, replace or delete there. The
		// socket itself is written by connecting to it, which is the
		// group's whole purpose; it is checked below for what it must
		// not grant.
		if name == "directory" {
			if err := checkACL(owner, dacl, false); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		var group *ace
		for i := range dacl {
			if dacl[i].SID == someGroup {
				group = &dacl[i]
			}
		}
		if group == nil {
			t.Fatalf("%s: the group is not granted anything: %s", name, sddl)
		}
		if hold := group.Mask & (writeDAC | writeOwner | accessDelete | genericAll | genericWrite | fileDeleteChild); hold != 0 {
			t.Errorf("%s: the group may change the ACL, the owner, or delete (0x%x)", name, hold)
		}
		if name == "directory" && group.Mask&writeRights != 0 {
			t.Errorf("%s: the group may add files (0x%x)", name, group.Mask)
		}
	}
	// On the directory the group may traverse and list, and gets nothing
	// that would be inherited by the files in it (helper.json).
	m := regexp.MustCompile(`\(A;([^;]*);[^;]*;;;` + someGroup + `\)`).FindStringSubmatch(dirSDDL(someGroup))
	if m == nil || m[1] != "" {
		t.Errorf("the group's directory entry is inherited by what is created there: %s", dirSDDL(someGroup))
	}
	_, dacl, _ := parseSDDL(t, dirSDDL(someGroup))
	for _, a := range dacl {
		if a.SID == someGroup && a.Mask&fileTraverse == 0 {
			t.Errorf("the group cannot traverse the directory to reach the socket")
		}
	}
	// On the socket it may read and write, which connecting takes.
	_, dacl, _ = parseSDDL(t, socketSDDL(someGroup))
	for _, a := range dacl {
		if a.SID == someGroup && a.Mask&(fileListDirectory|fileAddFile) != fileListDirectory|fileAddFile {
			t.Errorf("the group cannot read and write the socket (0x%x)", a.Mask)
		}
	}
}

// ProgramData's own descriptor -- what a directory created there inherits
// -- lets Users create files: exactly what the protected DACL is for, and
// what the check must refuse.
func TestProgramDataDefaultsAreRefused(t *testing.T) {
	programData := "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;LCSWWPLORC;;;BU)"
	// The descriptor names rights this parser does not know (SW, LO, RC);
	// what matters is the WP/LC entry for Users, so read it with those
	// mapped to nothing.
	programData = strings.Replace(programData, "LCSWWPLORC", "0x6", 1)
	owner, dacl, _ := parseSDDL(t, programData)
	err := checkACL(owner, dacl, false)
	if err == nil || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Errorf("ProgramData's ACL, which lets Users add files, was taken: %v", err)
	}
}

func TestCheckACL(t *testing.T) {
	full := uint32(0x1f01ff)
	for _, c := range []struct {
		name    string
		owner   string
		dacl    []ace
		nilDACL bool
		ok      bool
	}{
		{"SYSTEM and Administrators only", sidSystem, []ace{{SID: sidSystem, Mask: full}, {SID: sidAdministrators, Mask: full}}, false, true},
		{"owned by Administrators", sidAdministrators, []ace{{SID: sidAdministrators, Mask: full}}, false, true},
		{"users may read", sidAdministrators, []ace{{SID: sidAdministrators, Mask: full}, {SID: "S-1-5-32-545", Mask: 0x120089}}, false, true},
		{"an empty DACL: nobody but the owner's implicit rights", sidSystem, nil, false, true},
		{"a user may write", sidSystem, []ace{{SID: "S-1-5-32-545", Mask: fileAddFile}}, false, false},
		{"a user may append", sidSystem, []ace{{SID: someGroup, Mask: fileAddSubdir}}, false, false},
		{"a user may change the DACL", sidSystem, []ace{{SID: someGroup, Mask: writeDAC}}, false, false},
		{"a user may take ownership", sidSystem, []ace{{SID: someGroup, Mask: writeOwner}}, false, false},
		{"a user may delete", sidSystem, []ace{{SID: someGroup, Mask: accessDelete}}, false, false},
		{"everyone GENERIC_ALL", sidSystem, []ace{{SID: "S-1-1-0", Mask: genericAll}}, false, false},
		{"everyone GENERIC_WRITE", sidSystem, []ace{{SID: "S-1-1-0", Mask: genericWrite}}, false, false},
		{"an object ACE grants too", sidSystem, []ace{{Type: 0x5, SID: "unparsed", Mask: fileAddFile}}, false, false},
		{"a callback ACE grants too", sidSystem, []ace{{Type: 0x9, SID: "unparsed", Mask: fileAddFile}}, false, false},
		{"a deny is no grant", sidSystem, []ace{{Type: 0x1, SID: "S-1-1-0", Mask: full}}, false, true},
		{"inherit-only applies to children", sidSystem, []ace{{Flags: aceInheritOnly, SID: "S-1-3-0", Mask: genericAll}}, false, true},
		{"a null DACL grants everything", sidSystem, nil, true, false},
		{"owned by a user", someGroup, []ace{{SID: sidSystem, Mask: full}}, false, false},
	} {
		err := checkACL(c.owner, c.dacl, c.nilDACL)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// The refusal names who may write, so an administrator can fix it.
func TestCheckACLNamesTheWriters(t *testing.T) {
	err := checkACL(sidSystem, []ace{{SID: someGroup, Mask: fileAddFile}, {SID: sidAdministrators, Mask: 0x1f01ff}}, false)
	if err == nil || !strings.Contains(err.Error(), someGroup) || strings.Contains(err.Error(), sidAdministrators) {
		t.Errorf("err = %v", err)
	}
	if err := checkACL(someGroup, nil, false); err == nil || !strings.Contains(err.Error(), fmt.Sprint(someGroup)) {
		t.Errorf("the owner is not named: %v", err)
	}
}

//go:build !windows

package helper

import (
	"os"
	"testing"

	"errors"
	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
)

// ⛔ The approvals file decides which servers get the machine's traffic: one
// root did not write is not read, and the helper fails closed.
func TestAnApprovalsFileNotRootsIsNotTrusted(t *testing.T) {
	v := newVPNServer(t)
	c, s, ups := helperFor(t)
	s.approvals.verify = checkOwner // the real check; root is not us (rootUID == 0)
	if os.Getuid() == 0 {
		t.Skip("running as root: the file would be root's")
	}
	if err := os.WriteFile(s.approvals.path, []byte(`{"version":1,"servers":[{"url":"`+v.URL+`","identity":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var na *helperclient.NotApprovedError
	err := connect(t, c, v.URL)
	if err == nil || errors.As(err, &na) || len(v.enroll) != 0 || len(*ups) != 0 {
		t.Errorf("a file a user wrote was trusted (or the failure was not closed): %v", err)
	}
}

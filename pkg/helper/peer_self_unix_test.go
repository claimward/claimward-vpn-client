//go:build linux || darwin || freebsd

package helper

import (
	"os"
	"testing"
)

func selfPeer(t *testing.T) Peer { return unixPeer(uint32(os.Getuid())) }

func TestUnixPeerRuleRootIsAdminAndNobodyElseIs(t *testing.T) {
	if p := unixPeer(0); !p.Admin || p.ID != "uid:0" {
		t.Errorf("root: %+v", p)
	}
	if p := unixPeer(501); p.Admin || p.ID != "uid:501" {
		t.Errorf("501: %+v", p)
	}
}

package wgtun

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// What the device answers to UAPI "get=1" for a tunnel with one peer, in the
// order device/uapi.go writes it.
const getAnswer = "private_key=00000000000000000000000000000000000000000000000000000000000000aa\n" +
	"listen_port=51820\n" +
	"public_key=00000000000000000000000000000000000000000000000000000000000000bb\n" +
	"preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
	"protocol_version=1\n" +
	"endpoint=203.0.113.7:51820\n" +
	"last_handshake_time_sec=1700000000\n" +
	"last_handshake_time_nsec=250000000\n" +
	"tx_bytes=1234\n" +
	"rx_bytes=98765\n" +
	"persistent_keepalive_interval=25\n" +
	"allowed_ip=10.2.0.0/16\n" +
	"allowed_ip=fd00::/64\n"

func TestParseInfoReadsThePeer(t *testing.T) {
	in, err := parseInfo(getAnswer)
	if err != nil {
		t.Fatal(err)
	}
	if in.Endpoint != "203.0.113.7:51820" || in.RxBytes != 98765 || in.TxBytes != 1234 {
		t.Errorf("got %+v", in)
	}
	if !slices.Equal(in.AllowedIPs, []string{"10.2.0.0/16", "fd00::/64"}) {
		t.Errorf("allowed ips %v", in.AllowedIPs)
	}
	if want := time.Unix(1700000000, 250000000); !in.LastHandshake.Equal(want) {
		t.Errorf("handshake %v, want %v", in.LastHandshake, want)
	}
}

// A peer that never shaked hands has no handshake time, not 1970.
func TestParseInfoNoHandshakeIsZero(t *testing.T) {
	in, err := parseInfo("public_key=00\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\ntx_bytes=0\nrx_bytes=0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !in.LastHandshake.IsZero() {
		t.Errorf("handshake %v", in.LastHandshake)
	}
}

func TestParseInfoRefusesWhatIsNotUAPI(t *testing.T) {
	for _, bad := range []string{
		"no equals sign\n",
		"endpoint=not-an-endpoint\n",
		"allowed_ip=10.0.0.0/99\n",
		"rx_bytes=-1\n",
		"tx_bytes=99999999999999999999999\n",
		"last_handshake_time_sec=-5\n",
		strings.Repeat("x=y\n", maxUAPILines+1),
	} {
		if _, err := parseInfo(bad); err == nil {
			t.Errorf("accepted %.40q", bad)
		}
	}
}

// A device that cannot be read, or answers what is not UAPI, is an error and
// no Info -- never a half-filled one.
func TestInfoOfRefusesAnUnreadableDevice(t *testing.T) {
	cfg := Config{DNS: []string{"10.0.0.1"}, MTU: 1400}
	if in, err := infoOf(func() (string, error) { return "", errors.New("closed") }, cfg); err == nil || !reflect.DeepEqual(in, Info{}) {
		t.Errorf("unreadable device: %+v, %v", in, err)
	}
	if in, err := infoOf(func() (string, error) { return "tx_bytes=1\nrx_bytes=nope\n", nil }, cfg); err == nil || !reflect.DeepEqual(in, Info{}) {
		t.Errorf("garbled answer: %+v, %v", in, err)
	}
	in, err := infoOf(func() (string, error) { return getAnswer, nil }, cfg)
	if err != nil || in.MTU != 1400 || !slices.Equal(in.DNS, cfg.DNS) || in.TxBytes != 1234 {
		t.Errorf("good answer: %+v, %v", in, err)
	}
}

func FuzzParseInfo(f *testing.F) {
	f.Add(getAnswer)
	f.Add("")
	f.Add("endpoint=[::1]:1\nallowed_ip=::/0\n")
	f.Fuzz(func(t *testing.T, s string) {
		in, err := parseInfo(s)
		if err != nil {
			return
		}
		if in.LastHandshake.Before(time.Unix(0, 0)) && !in.LastHandshake.IsZero() {
			t.Errorf("handshake before the epoch: %v", in.LastHandshake)
		}
	})
}

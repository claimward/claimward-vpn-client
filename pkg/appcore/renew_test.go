package appcore

import (
	"context"
	"testing"
	"time"
)

// asked is a snapshot of what the world's server was asked, of one kind.
func askedOf(asked *[]string, kind string) []string {
	worldMu.Lock()
	defer worldMu.Unlock()
	var out []string
	for _, a := range *asked {
		if len(a) >= len(kind) && a[:len(kind)] == kind {
			out = append(out, a)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
	}
}

// While the tunnel is up the app brings the helper fresh bearers, and the
// helper renews the lease with them; disconnecting stops that and gives
// the address back.
func TestTheAppKeepsTheLeaseRenewed(t *testing.T) {
	c, asked := world(t)
	c.renewAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	if err := c.SetTenant(""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant("hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "renewals", func() bool { return len(askedOf(asked, "heartbeat")) >= 2 })
	if hb := askedOf(asked, "heartbeat"); hb[0] != "heartbeat Bearer a.b.c" {
		t.Errorf("renewed with %q", hb[0])
	}
	if err := c.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := askedOf(asked, "deregister"); len(d) != 1 {
		t.Errorf("deregistered %d times", len(d))
	}
	n := len(askedOf(asked, "heartbeat"))
	time.Sleep(30 * time.Millisecond)
	if m := len(askedOf(asked, "heartbeat")); m != n {
		t.Errorf("%d renewals after disconnecting", m-n)
	}
}

// An app restarted under a running tunnel renews it too, from its first
// Status; and stops when the helper no longer has a tunnel.
func TestARestartedAppRenewsATunnelItDidNotBringUp(t *testing.T) {
	c, asked := world(t)
	if _, err := c.Tenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant("hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Disconnect(context.Background()) // stops c's loop; brought up again below
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.stopRenew()
	c.mu.Unlock()

	restarted := New(&Config{ServerURL: c.Config().ServerURL, Provider: "oidc", OIDCIssuer: "https://login.example.org",
		OIDCClientID: "claimward", SocketPath: c.Config().SocketPath})
	restarted.renewAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	before := len(askedOf(asked, "heartbeat"))
	if st := restarted.Status(); !st.Connected {
		t.Fatal("not connected")
	}
	waitFor(t, "renewals from the restarted app", func() bool { return len(askedOf(asked, "heartbeat")) >= before+2 })

	// The helper's tunnel goes away under it: the loop notices and ends,
	// and the next Status may start another.
	if _, err := restarted.helper.Down(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the loop to end", func() bool {
		restarted.mu.Lock()
		defer restarted.mu.Unlock()
		return restarted.stopRenew == nil
	})
}

func TestAppRenewalTiming(t *testing.T) {
	for _, c := range []struct{ left, want time.Duration }{
		{24 * time.Hour, 50 * time.Minute},
		{50 * time.Minute, 20 * time.Minute},
		{10 * time.Second, 20 * time.Second},
	} {
		if got := renewDelay(c.left); got != c.want {
			t.Errorf("renewDelay(%v) = %v, want %v", c.left, got, c.want)
		}
	}
}

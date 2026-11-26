package exclusive

import (
	"errors"
	"strings"
	"testing"
)

var (
	plainA = Member{URL: "https://a.example", Name: "Alpha"}
	plainB = Member{URL: "https://b.example"}
	solo   = Member{URL: "https://s.example", Name: "Solo", Exclusive: true}
)

func TestTwoPlainServersMayShare(t *testing.T) {
	if err := Check(plainA, []Member{plainB}); err != nil {
		t.Fatal(err)
	}
}

func TestNothingConnectedAlwaysAllowed(t *testing.T) {
	if err := Check(solo, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveRefusedWhileAnotherIsConnected(t *testing.T) {
	err := Check(solo, []Member{plainA})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if e.BlockedBy() != "Alpha" || e.Server.URL != solo.URL {
		t.Fatalf("%+v", e)
	}
	if !strings.Contains(err.Error(), "Solo is exclusive") || !strings.Contains(err.Error(), "Alpha") {
		t.Fatalf("message %q", err)
	}
}

func TestOtherRefusedWhileExclusiveIsConnected(t *testing.T) {
	err := Check(plainA, []Member{solo})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if e.BlockedBy() != "Solo" {
		t.Fatalf("blocked by %q", e.BlockedBy())
	}
	if !strings.Contains(err.Error(), "Solo is exclusive and is connected") {
		t.Fatalf("message %q", err)
	}
}

func TestLabelFallsBackToURL(t *testing.T) {
	err := Check(solo, []Member{plainB})
	if got := err.(*Error).BlockedBy(); got != "https://b.example" {
		t.Fatalf("got %q", got)
	}
}

func TestReconnectingTheSameServerIsNotBlockedByItself(t *testing.T) {
	if err := Check(solo, []Member{solo}); err != nil {
		t.Fatal(err)
	}
	if err := Check(plainA, []Member{plainA, plainB}); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveAmongSeveralIsFound(t *testing.T) {
	err := Check(plainA, []Member{plainB, solo})
	var e *Error
	if !errors.As(err, &e) || e.Blocker.URL != solo.URL {
		t.Fatalf("err = %v", err)
	}
}

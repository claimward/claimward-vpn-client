package tokenstore

import (
	"errors"
	"testing"
)

// scripted is a backend with a fixed document and a count of its writes.
type scripted struct {
	data     []byte
	getErr   error
	delErr   error
	sets     int
	dels     int
	lastData []byte
}

func (s *scripted) get() ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.data == nil {
		return nil, errNotFound
	}
	return s.data, nil
}
func (s *scripted) set(b []byte) error { s.sets++; s.lastData = b; return nil }
func (s *scripted) del() error         { s.dels++; return s.delErr }

func useScripted(t *testing.T, b *scripted) {
	t.Helper()
	m := useMemory(t)
	_ = m
	store = b
}

const twoSessions = `{"version":2,"sessions":{"https://a.example github":{"bearer":"A"},"\u0000legacy":{"bearer":"L"}}}`

func TestDecodeRefusesAWrongTypedVersion(t *testing.T) {
	// The probe fails on the version, though the same bytes read as a session.
	if _, err := decode([]byte(`{"version":"two"}`)); err == nil {
		t.Fatal("decoded a document whose version is a string")
	}
}

func TestDecodeRefusesAWrongTypedSession(t *testing.T) {
	if _, err := decode([]byte(`{"version":2,"sessions":{"k":"text"}}`)); err == nil {
		t.Fatal("decoded a session that is a string")
	}
}

func TestClearingTheLastSessionReportsTheBackendFailure(t *testing.T) {
	boom := errors.New("del failed")
	b := &scripted{data: []byte(`{"version":2,"sessions":{"k":{"bearer":"A"}}}`), delErr: boom}
	useScripted(t, b)
	if err := Clear("k"); !errors.Is(err, boom) {
		t.Fatalf("Clear = %v, want %v", err, boom)
	}
}

func TestAnUnreadableStoreIsAnErrorEverywhere(t *testing.T) {
	boom := errors.New("locked")
	b := &scripted{getErr: boom}
	useScripted(t, b)
	if s, err := Load("k"); err == nil || s != nil {
		t.Errorf("Load = %+v, %v", s, err)
	}
	if err := Clear("k"); !errors.Is(err, boom) {
		t.Errorf("Clear = %v", err)
	}
	if ok, err := AdoptLegacy("k"); err == nil || ok {
		t.Errorf("AdoptLegacy = %v, %v", ok, err)
	}
	if err := DiscardLegacy(); !errors.Is(err, boom) {
		t.Errorf("DiscardLegacy = %v", err)
	}
	if b.sets != 0 || b.dels != 0 {
		t.Errorf("a store that could not be read was written: %d sets, %d dels", b.sets, b.dels)
	}
}

func TestSaveKeepsTheNoSecretStoreErrorUnwrapped(t *testing.T) {
	b := &scripted{getErr: ErrNoSecretStore}
	useScripted(t, b)
	if err := Save("k", &Session{Bearer: "x"}); err != ErrNoSecretStore {
		t.Fatalf("Save = %v, want ErrNoSecretStore itself", err)
	}
}

func TestDiscardingAbsentLegacyWritesNothing(t *testing.T) {
	b := &scripted{data: []byte(`{"version":2,"sessions":{"k":{"bearer":"A"}}}`)}
	useScripted(t, b)
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
	if b.sets != 0 || b.dels != 0 {
		t.Fatalf("nothing to discard, yet %d sets, %d dels", b.sets, b.dels)
	}
}

func TestDiscardingLegacyKeepsTheOthers(t *testing.T) {
	b := &scripted{data: []byte(twoSessions)}
	useScripted(t, b)
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
	if b.sets != 1 {
		t.Fatalf("sets = %d", b.sets)
	}
}

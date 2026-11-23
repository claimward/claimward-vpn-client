package tokenstore

import "sync"

// memBackend keeps the session in this process's memory and nowhere else.
type memBackend struct {
	mu   sync.Mutex
	data []byte
}

func (m *memBackend) get() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, errNotFound
	}
	return append([]byte(nil), m.data...), nil
}

func (m *memBackend) set(b []byte) error {
	m.mu.Lock()
	m.data = append([]byte(nil), b...)
	m.mu.Unlock()
	return nil
}

func (m *memBackend) del() error {
	m.mu.Lock()
	m.data = nil
	m.mu.Unlock()
	return nil
}

// UseMemory replaces the platform's secret store with one held in this
// process's memory, for the tests of packages that use tokenstore (they must
// not touch the person's real Keychain, Credential Store or Secret Service).
// Nothing is ever written to disk. It returns the function that restores the
// platform store.
func UseMemory() (restore func()) {
	old := store
	store = &memBackend{}
	return func() { store = old }
}

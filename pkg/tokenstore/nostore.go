package tokenstore

// noStore is the backend of a machine with no secret store: nothing can be
// read from it and saving is refused. There is no file fallback.
type noStore struct{}

func (noStore) get() ([]byte, error) { return nil, errNotFound }
func (noStore) set([]byte) error     { return ErrNoSecretStore }
func (noStore) del() error           { return nil }

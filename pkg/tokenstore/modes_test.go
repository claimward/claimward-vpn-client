package tokenstore

import "runtime"

// runtimeHasUnixModes reports whether file permission bits mean anything here.
func runtimeHasUnixModes() bool { return runtime.GOOS != "windows" }

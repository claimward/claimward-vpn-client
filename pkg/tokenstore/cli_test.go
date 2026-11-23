package tokenstore

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestFakeCLI is not a test: it is the stand-in for /usr/bin/security and
// secret-tool, which the tests run by re-executing this test binary. What it
// does is set by FAKE_CLI_* variables:
//
//	FAKE_CLI_OUT        printed on standard output
//	FAKE_CLI_EXIT       the exit status (default 0)
//	FAKE_CLI_STDERR     printed on standard error
//	FAKE_CLI_STDIN_FILE standard input is copied there
//	FAKE_CLI_ARGS_FILE  the arguments after "--", one per line, are written there
func TestFakeCLI(t *testing.T) {
	if os.Getenv("FAKE_CLI") != "1" {
		t.Skip("only runs as the stand-in for a command line tool")
	}
	if f := os.Getenv("FAKE_CLI_STDIN_FILE"); f != "" {
		in, _ := io.ReadAll(os.Stdin)
		os.WriteFile(f, in, 0o600)
	}
	if f := os.Getenv("FAKE_CLI_ARGS_FILE"); f != "" {
		args := os.Args
		for i, a := range args {
			if a == "--" {
				args = args[i+1:]
				break
			}
		}
		os.WriteFile(f, []byte(strings.Join(args, "\n")), 0o600)
	}
	fmt.Fprint(os.Stdout, os.Getenv("FAKE_CLI_OUT"))
	fmt.Fprint(os.Stderr, os.Getenv("FAKE_CLI_STDERR"))
	code, _ := strconv.Atoi(os.Getenv("FAKE_CLI_EXIT"))
	os.Exit(code)
}

// fakeCLI returns the command line that runs TestFakeCLI, with the behaviour
// set through the environment.
func fakeCLI(t *testing.T, env map[string]string) []string {
	t.Helper()
	t.Setenv("FAKE_CLI", "1")
	for _, k := range []string{"FAKE_CLI_OUT", "FAKE_CLI_EXIT", "FAKE_CLI_STDERR", "FAKE_CLI_STDIN_FILE", "FAKE_CLI_ARGS_FILE"} {
		t.Setenv(k, env[k])
	}
	return []string{os.Args[0], "-test.run=^TestFakeCLI$", "--"}
}

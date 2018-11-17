package main

import (
	"os"
	"path"
	"testing"

	"github.com/dlespiau/covertool/pkg/cover"
	"github.com/dlespiau/covertool/pkg/exit"
)

func TestMain(m *testing.M) {
	cover.ParseAndStripTestFlags()

	// Make sure we have the opportunity to flush the coverage report to disk when
	// terminating the process.
	exit.AtExit(cover.FlushProfiles)

	// If the test binary name is "calc" we've are being asked to run the
	// coverage-instrumented calc.
	if path.Base(os.Args[0]) == "broker-cover.exe" {
		main()
		exit.Exit(0)
	}

	os.Exit(m.Run())
}

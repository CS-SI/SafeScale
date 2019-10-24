package utils

import (
	"fmt"
	"github.com/gregoryv/gocyclo"
	"path/filepath"
	"testing"
)

func complexityTester(maximum int, subdir string, t *testing.T) {
	files, err := filepath.Glob(fmt.Sprintf("./%s/*.go", subdir))
	if err != nil {
		t.Fatal(err)
	}

	max := maximum
	result, ok := gocyclo.Assert(files, max)
	if !ok {
		for _, l := range result {
			t.Log(l)
		}
		t.Errorf("Exceeded maximum complexity %v", max)
	}
}

func TestComplexity(t *testing.T) {
	// FIXME In time, not a single subpackage complexity should be greater than 25

	complexityTester(20, "cluster", t)
	complexityTester(110, "handlers", t) // FIXME Reduce complexity
	complexityTester(48, "iaas", t)      // FIXME Reduce complexity
	complexityTester(51, "install", t)   // FIXME Reduce complexity
	complexityTester(20, "listeners", t)
	complexityTester(20, "metadata", t)
	complexityTester(20, "utils", t)
}

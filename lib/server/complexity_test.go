package utils

import (
    "path/filepath"
    "testing"

    "github.com/gregoryv/gocyclo"
)

func Test_complexity(t *testing.T) {
    files, err := filepath.Glob("./**/*.go")
    if err != nil {
        t.Fatal(err)
    }

    max := 25
    result, ok := gocyclo.Assert(files, max)
    if !ok {
        for _, l := range result {
            t.Log(l)
        }
        t.Errorf("Exceeded maximum complexity %v", max)
    }
}

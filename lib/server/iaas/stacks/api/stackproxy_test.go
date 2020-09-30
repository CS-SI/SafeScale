package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func Test_errorTranslator(t *testing.T) {
	nerr := fail.AbortedError("Ouch", nil)

	terr := errorTranslator(nerr)
	if terr == nil {
		t.FailNow()
	}

	text := terr.Error()
	if strings.Contains(text, "wrapped") {
		t.Fail()
	}

	classic := fmt.Errorf("error: %s", "happened")
	terr = errorTranslator(classic)
	if terr == nil {
		t.FailNow()
	}

	text = terr.Error()
	if !strings.Contains(text, "wrapped") {
		t.Fail()
	}
}

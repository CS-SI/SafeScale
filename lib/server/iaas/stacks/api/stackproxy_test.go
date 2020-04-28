package api

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"strings"
	"testing"
)

func Test_errorTranslator(t *testing.T) {
	nerr := scerr.AbortedError("Ouch", nil)

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

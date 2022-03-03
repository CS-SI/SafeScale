package callstack

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func gotSoLow(count uint) string {
	err := fmt.Errorf("let's talk, hope you understand")
	daylight := DecorateWith("", "", fmt.Sprintf("Unhandled error (%s) received from provider: %s", reflect.TypeOf(err).String(), err.Error()), count)
	return daylight
}

func stay(count uint) string {
	var response = gotSoLow(count)
	return response
}

func hit(count uint) string {
	var response = stay(count)
	return response
}

func paradise(count uint) string {
	var response = hit(count)
	return response
}

func Test_DecorateWith(t *testing.T) {

	// 0 and 1 are equivalent by design -> when DecorateWith receives 0, it actually returns 1; receiving 1 also returns 1
	the := paradise(0)
	if !strings.Contains(the, "callstack_test.go:12") {
		t.Errorf("First check failed: %s", the)
	}

	perfect := paradise(1)
	if !strings.Contains(perfect, "callstack_test.go:12") {
		t.Errorf("2nd check failed")
	}
	creatures := paradise(2)
	if !strings.Contains(creatures, "callstack_test.go:17") {
		t.Errorf("3rd check failed")
	}

	stars := paradise(3)
	if !strings.Contains(stars, "callstack_test.go:22") {
		t.Errorf("3rd check failed")
	}

}

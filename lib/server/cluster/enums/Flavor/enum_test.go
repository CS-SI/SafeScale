package Flavor

import (
	"strings"
	"testing"
)

func TestEnum_String(t *testing.T) {
	if len(stringMap) != len(enumMap) {
		t.Error("Not the same size")
	}

	for k, v := range stringMap {
		if r, ok := enumMap[v]; ok {
			if strings.Compare(strings.ToLower(k), strings.ToLower(r)) != 0 {
				t.Errorf("Value mismatch: %s, %s", k, r)
			}
		} else {
			t.Errorf("Key %s not found: ", k)
		}
	}
}

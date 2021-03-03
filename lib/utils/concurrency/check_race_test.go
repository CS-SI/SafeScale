// +build !race

package concurrency

import "testing"

func TestRaceBuild(t *testing.T) {
	t.Errorf("The -race flag MUST be ALWAYS enabled, here it's not")
	t.FailNow()
}

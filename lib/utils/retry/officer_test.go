package retry

import (
	"testing"
	"time"
)

func TestFibonacci(t *testing.T) {
	now := time.Now()
	got := Fibonacci(100 * time.Millisecond)
	got.Block(Try{}) // 100 +- 10
	got.Block(Try{}) // 200 +- 10
	got.Block(Try{}) // 300 +- 10
	got.Block(Try{}) // 500 +- 10
	elapsed := time.Since(now)
	if elapsed < 1000*time.Millisecond || elapsed > 1200*time.Millisecond {
		t.Errorf("this should have been 1100 +- 40 ms: %s", elapsed)
		t.FailNow()
	}
}

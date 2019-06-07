package retry

import (
	"math"
	"time"
)

// Officer sleeps or selects any amount of time for each try
type Officer struct {
	Block func(Try)
}

// Constant sleeps for duration duration
func Constant(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration)
		},
	}
	return &o
}

// Incremental sleeps for duration + the number of tries
func Incremental(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration + time.Duration(t.Count))
		},
	}
	return &o

}

// Linear sleeps for duration * the number of tries
func Linear(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration * time.Duration(t.Count))
		},
	}
	return &o
}

// Exponential sleeps for duration base * 2^tries
func Exponential(base time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(time.Duration(float64(base) * math.Exp(float64(t.Count))))
		},
	}
	return &o
}

// Fibonacci sleeps for duration * fib(tries)
//TODO:See if we can use a context to prevent the full calculation for each try...
func Fibonacci(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			var pre int64
			var cur int64
			var i uint
			for pre, cur, i = 0, 1, 0; i < t.Count; i++ {
				pre = cur
				cur = pre + cur
			}
			time.Sleep(duration * time.Duration(pre))
		},
	}
	return &o
}

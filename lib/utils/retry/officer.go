package retry

import (
	"math"
	"time"
)

// Officer sleeps or selects any amount of time for each try
type Officer struct {
	Block func(Try)

	params interface{}
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
// TODO: See if we can use a context to prevent the full calculation for each try...
func Fibonacci(base time.Duration) *Officer {
	o := Officer{
		params: map[string]uint64{"pre": 0, "cur": 1},
	}
	o.Block = func(t Try) {
		p := o.params.(map[string]uint64)
		cur := p["cur"]
		pre := p["pre"]
		p["pre"] = cur
		cur += pre
		p["cur"] = cur

		time.Sleep(base * time.Duration(pre))
	}

	return &o
}

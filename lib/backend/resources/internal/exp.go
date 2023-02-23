package internal

import (
	"expvar"

	"github.com/zserge/metric"
)

func IncrementExpVar(name string) {
	// increase counter
	ts := expvar.Get(name)
	if ts != nil {
		switch casted := ts.(type) {
		case *expvar.Int:
			casted.Add(1)
		case metric.Metric:
			casted.Add(1)
		}
	}
}

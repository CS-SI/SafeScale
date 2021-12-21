package exportstats

import (
	"expvar"
	"fmt"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"
)

var stats *expvar.Map

// Example:
//  NewStatCount("stats")
//  ..
//  Increment("active_ws_users")
//  defer Decrement("active_ws_users")
//  doWebSocket()

// Recommend using expvarmon (see https://github.com/divan/expvarmon )
//   expvarmon  -ports="http://localhost:9000" -i=1s \
//   -vars="goroutines,stats.auth_failures,stats.open_ws,stats.rabbit_messages_rx,stats.rabbit_reconnections, \
//   mem:memstats.Alloc,mem:memstats.Sys,mem:memstats.HeapAlloc,mem:memstats.HeapInuse"

// NewStatCount sets up a stat counter
// See http://go-talks.appspot.com/github.com/sajari/talks/201610/simplifying-storage/storage.slide#36 for more
// or http://www.mikeperham.com/2014/12/17/expvar-metrics-for-golang/ or http://blog.ralch.com/tutorial/golang-metrics-with-expvar/
func NewStatCount(statName string) {
	stats = expvar.NewMap(statName)

	// Export goroutines
	expvar.Publish("goroutines", expvar.Func(func() interface{} {
		return fmt.Sprintf("%d", runtime.NumGoroutine())
	}))

	// Init
	expvar.Publish("waitinit", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("runinit", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("waitnetsec", metric.NewCounter("5m1s", "15m30s", "1h1m"))
	expvar.Publish("runnetsec", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("waitgwha", metric.NewHistogram("5m1s", "15m30s", "1h1m"))
	expvar.Publish("rungwha", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("waitsysfix", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("runsysfix", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("waitfinal", metric.NewGauge("5m1s", "15m30s", "1h1m"))
	expvar.Publish("runfinal", metric.NewGauge("5m1s", "15m30s", "1h1m"))
}

// Increment a certain stat
func Increment(stat string) {
	if stats == nil {
		logrus.Println("Increment failed - did you forget to call NewStatCount")
		return
	}
	stats.Add(stat, 1)
}

// Decrement a certain stat
func Decrement(stat string) {
	if stats == nil {
		logrus.Println("Decrement failed - did you forget to call NewStatCount")
		return
	}
	stats.Add(stat, -1)
}

// SetInt sets a particular particular stat to a specific integer value
func SetInt(stat string, n int64) {
	if stats == nil {
		logrus.Println("Decrement failed - did you forget to call NewStatCount")
		return
	}
	stats.Get(stat).(*expvar.Int).Set(n)
}

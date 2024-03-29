/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package exportstats

import (
	"expvar"
	"fmt"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"
)

var stats *expvar.Map

// NewStatCount sets up a stat counter
func NewStatCount(statName string) {
	stats = expvar.NewMap(statName)

	// Export goroutines
	expvar.Publish("goroutines", expvar.Func(func() interface{} {
		return fmt.Sprintf("%d", runtime.NumGoroutine())
	}))

	// Monitoring stow cache
	expvar.Publish("readobject", metric.NewCounter("5m15s", "15m1m", "1h5m"))
	expvar.Publish("writeobject", metric.NewCounter("5m15s", "15m1m", "1h5m"))
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

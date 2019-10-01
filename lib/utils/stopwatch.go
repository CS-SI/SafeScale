/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
)

const outputStopwatchTemplate = "%s (elapsed: %s)"

// Stopwatch allows to time duration
type Stopwatch struct {
	start    time.Time
	stopped  bool
	duration time.Duration
}

// Start starts the Stopwatch
func (sw Stopwatch) Start() {
	sw.start = time.Now()
}

// Stop stops the Stopwatch
func (sw Stopwatch) Stop() {
	sw.stopped = true
	sw.duration += time.Since(sw.start)
}

// Duration returns the time elapsed since the Stopwatch has been started
func (sw Stopwatch) Duration() time.Duration {
	if sw.stopped {
		return sw.duration
	}
	return time.Since(sw.start)
}

// String returns a string representation of duration
func (sw Stopwatch) String() string {
	return FormatDuration(sw.Duration())
}

// OnExitLogWithLevel logs 'in' with log level 'level', then returns a function (to be used with defer for example)
// that will log 'out' + elapsed time
func (sw Stopwatch) OnExitLogWithLevel(in, out string, level logrus.Level) func() {
	logLevelFn, ok := logLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Info
	}

	// In the meantime, if both 'in' and 'out' are empty, recover function name from caller...
	if len(in) == 0 && len(out) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				in = filepath.Base(f.Name())
				out = filepath.Base(f.Name()) + " called"
			}
		}
	}

	logLevelFn(in)

	sw.Start()
	return func() {
		sw.Stop()
		logLevelFn(fmt.Sprintf(outputStopwatchTemplate, out, FormatDuration(sw.Duration())))
	}
}

// OnExitLogInfo logs 'in' in Info level then returns a function that will log 'out' with elapsed time
func (sw Stopwatch) OnExitLogInfo(in, out string) func() {
	return sw.OnExitLogWithLevel(in, out, logrus.InfoLevel)
}

// FormatDuration ...
func FormatDuration(dur time.Duration) string {
	ms := (dur.Nanoseconds() % 1000000000) / 1000000
	if ms == 0 {
		if dur.Nanoseconds()/1000000000 == 0 {
			ms = 1
			return fmt.Sprintf("%d ms", ms)
		}
	}

	sec := int64(dur.Truncate(time.Second).Seconds()) % 60
	min := int64(dur.Truncate(time.Minute).Minutes())

	if min == 0 {
		return fmt.Sprintf("%d seconds, %d ms", sec, ms)
	}

	return fmt.Sprintf("%d minutes, %d seconds, %d ms", min, sec, ms)
}

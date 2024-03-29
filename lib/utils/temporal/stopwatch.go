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

package temporal

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/commonlog"
)

//go:generate minimock -o mocks/mock_stopwatch.go -i github.com/CS-SI/SafeScale/v22/lib/utils/temporal.Stopwatch

// Stopwatch interface to expose methods available for a stopwatch
type Stopwatch interface {
	// Start starts the stopwatch, either for the first time or after a Pause()
	Start()
	// Stop stops definitively the stopwatch, disabling the ability to start it again
	Stop()
	// Pause stops temporarily the stopwatch, allowing to start it again, suming up the time intervals
	Pause()
	// GetDuration returns the current elapsed time measured by the Stopwatch
	GetDuration() time.Duration
	// String returns a printable representation of the current elapsed time
	String() string
	// OnExitLogWithLevel returns a function that will log start and end of Stopwatch, intended tto be used with defer
	OnExitLogWithLevel(ctx context.Context, in, out string, level logrus.Level) func()

	OnExitLogInfo(ctx context.Context, in, out string) func()
}

// stopwatch is the implementation satisfying interface Stopwatch
type stopwatch struct {
	start    time.Time
	running  bool
	stopped  bool
	duration time.Duration
}

// NewStopwatch creates a object satisfying interface Stopwatch
func NewStopwatch() Stopwatch {
	return &stopwatch{}
}

// We need Stopwatch pointer receivers in order to change the underlying struct

// Start starts the Stopwatch
func (sw *stopwatch) Start() {
	if !sw.running && !sw.stopped {
		sw.start = time.Now()
		sw.running = true
	}
}

// Stop stops the Stopwatch
func (sw *stopwatch) Stop() {
	sw.stopped = true
	if sw.running {
		sw.duration += time.Since(sw.start)
		sw.running = false
	}
}

// Pause pauses the Stopwatch, which can then unpause by calling Start again
func (sw *stopwatch) Pause() {
	if sw.stopped {
		return
	}
	if sw.running {
		if !sw.start.IsZero() {
			sw.duration += time.Since(sw.start)
		}
		sw.running = false
	}
}

// GetDuration returns the time elapsed since the Stopwatch has been started
func (sw *stopwatch) GetDuration() time.Duration {
	if sw.stopped {
		return sw.duration
	}
	if sw.running {
		return sw.duration + time.Since(sw.start)
	}
	return time.Duration(0)
}

// String returns a string representation of duration
func (sw *stopwatch) String() string {
	return FormatDuration(sw.GetDuration())
}

// OnExitLogWithLevel logs 'in' with log level 'level', then returns a function (to be used with defer for example)
// that will log 'out' + elapsed time
func (sw *stopwatch) OnExitLogWithLevel(ctx context.Context, in, out string, level logrus.Level) func() {
	if in == "" && out == "" {
		return func() {}
	}

	logLevelFn := commonlog.LogLevelFnMap(ctx, level)
	if logLevelFn != nil {
		logLevelFn(in)

		sw.Start()
		return func() {
			sw.Stop()
			logLevelFn(fmt.Sprintf("%s (elapsed: %s)", out, FormatDuration(sw.GetDuration()))) // nolint
		}
	}

	return func() {}
}

// OnExitLogInfo logs 'in' in Info level then returns a function that will log 'out' with elapsed time
func (sw *stopwatch) OnExitLogInfo(ctx context.Context, in, out string) func() {
	return sw.OnExitLogWithLevel(ctx, in, out, logrus.InfoLevel)
}

// FormatDuration ...
func FormatDuration(dur time.Duration) string {
	ms := (dur.Nanoseconds() % 1000000000) / 1000000
	if ms == 0 {
		if dur.Nanoseconds()/1000000000 == 0 {
			ms = 1
			// return fmt.Sprintf("%.03d s", ms)
		}
	}

	sec := int64(dur.Truncate(time.Second).Seconds()) % 60
	min := int64(dur.Truncate(time.Minute).Minutes())
	return fmt.Sprintf("00h%02dm%02d.%03ds", min, sec, ms)
}

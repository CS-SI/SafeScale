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

package loghelpers

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

const outputStopwatchTemplate = "%s (elapsed: %s)"

// LogStopwatchWithLevelCallback logs 'in' with log level 'level', then returns a function that'll log 'in' + elapsed time,
// to be used with defer
func LogStopwatchWithLevelCallback(in, out string, tracer *concurrency.Tracer, level logrus.Level) func() {
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

	if tracer != nil {
		tracer.In()
	}
	logLevelFn(in)

	start := time.Now()
	return func() {
		logLevelFn(fmt.Sprintf(outputStopwatchTemplate, out, FormatDuration(time.Since(start))))
	}
}

// LogInfoStopwatchCallback returns a func that logs message in Info level adding time elapsed
func LogInfoStopwatchCallback(in, out string, tracer *concurrency.Tracer) func() {
	return LogStopwatchWithLevelCallback(in, out, tracer, logrus.InfoLevel)
}

// LogStopwatchWithLevelAndErrorCallback logs 'in' with level 'level', then returns a func that'll log 'in' with elasped time and
// error (in logrus.ErrorLevel) if error occured, for use with defer
func LogStopwatchWithLevelAndErrorCallback(in, out string, tracer *concurrency.Tracer, err *error, level logrus.Level) func() {
	logLevelFn, ok := logLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Debug
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

	if tracer != nil {
		tracer.In()
	}
	logLevelFn(in)

	start := time.Now()
	return func() {
		if err == nil || *err == nil {
			logLevelFn(fmt.Sprintf(outputStopwatchTemplate, out, FormatDuration(time.Since(start))))
		} else {
			LogErrorCallback(in, tracer, err)()
			// logrus.Error(fmt.Sprintf(outputStopwatchAndErrorTemplate, msgOut, formatDuration(time.Since(start))), *err)
		}
		if tracer != nil {
			tracer.Out()
		}
	}
}

// LogInfoStopwatchWithErrorCallback logs 'in' in level Info then returns a func that'll log 'in' augmented with time elapsed and
// error (if an error happened), to use with defer
func LogInfoStopwatchWithErrorCallback(in, out string, tracer *concurrency.Tracer, err *error) func() {
	return LogStopwatchWithLevelAndErrorCallback(in, out, tracer, err, logrus.InfoLevel)
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

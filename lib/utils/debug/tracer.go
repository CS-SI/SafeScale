/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package debug

import (
	"path/filepath"
	"runtime"
	godebug "runtime/debug"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Tracer ...
type Tracer interface {
	WithStopwatch() Tracer
	EnteringMessage() string
	Entering() Tracer
	ExitingMessage() string
	Exiting() Tracer
	TraceMessage(msg ...interface{}) string
	Trace(msg ...interface{}) Tracer
	TraceAsError(msg ...interface{}) Tracer
	Stopwatch() temporal.Stopwatch
}

// tracer ...
type tracer struct {
	taskSig      string
	fileName     string
	funcName     string
	callerParams string
	enabled      bool
	inDone       bool
	outDone      bool
	sw           temporal.Stopwatch
}

const (
	unknownFunction string = "<unknown function>"
	unknownFile     string = "<unknown file>"
	goingInPrefix   string = ">>> "
	goingOutPrefix  string = "<<< "
)

// NewTracer creates a new Tracer instance
func NewTracer(task concurrency.Task, enable bool, msg ...interface{}) Tracer {
	t := tracer{
		enabled: enable,
	}
	if task != nil {
		t.taskSig = task.Signature()
	}

	message := strprocess.FormatStrings(msg...)
	if message == "" {
		message = "()"
	}
	t.callerParams = strings.TrimSpace(message)

	// Build the message to trace
	// VPL: ma version
	// if pc, file, line, ok := runtime.Caller(1); ok {
	//	if f := runtime.FuncForPC(pc); f != nil {
	//		t.funcName = f.Name()
	//		filename := strings.Replace(file, debug.sourceFilePartToRemove(), "", 1)
	//		t.inOutMessage = fmt.Sprintf("%s %s%s [%s:%d]", t.taskSig, filepath.Base(t.funcName), message, filename, line)
	//	}
	// }
	// VPL: la version d'Oscar
	if pc, file, _, ok := runtime.Caller(1); ok {
		t.fileName = callstack.SourceFilePathUpdater()(file)
		if f := runtime.FuncForPC(pc); f != nil {
			t.funcName = filepath.Base(f.Name())
		}
	}
	if t.funcName == "" {
		t.funcName = unknownFunction
	}
	if t.fileName == "" {
		t.funcName = unknownFile
	}

	return &t
}

// IsNull returns true if the instance is a null value of tracer
func (t *tracer) IsNull() bool {
	return t == nil || (t.callerParams == "" && (t.funcName == unknownFunction || t.fileName == unknownFile))
}

// EnteringMessage returns the content of the message when entering the function
func (t *tracer) EnteringMessage() string {
	if t.IsNull() {
		return ""
	}
	return goingInPrefix + t.buildMessage()
}

// WithStopwatch will add a measure of duration between GoingIn and Exiting.
// Exiting will add the elapsed time in the log message (if it has to be logged...).
func (t *tracer) WithStopwatch() Tracer {
	if t.sw == nil {
		t.sw = temporal.NewStopwatch()
	}
	return t
}

// Entering logs the input message (signifying we are going in) using TRACE level
func (t *tracer) Entering() Tracer {
	if !t.IsNull() && !t.inDone {
		if t.sw != nil {
			t.sw.Start()
		}
		if t.enabled {
			t.inDone = true
			msg := goingInPrefix + t.buildMessage()
			if msg != "" {
				logrus.Tracef(msg)
			}
		}
	}
	return t
}

// ExitingMessage returns the content of the message when exiting the function
func (t *tracer) ExitingMessage() string {
	if t.IsNull() {
		return ""
	}
	return goingOutPrefix + t.buildMessage()
}

// Exiting logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (t *tracer) Exiting() Tracer {
	if !t.IsNull() && !t.outDone {
		if t.sw != nil {
			t.sw.Stop()
		}
		if t.enabled {
			t.outDone = true
			msg := goingOutPrefix + t.buildMessage()
			if t.sw != nil {
				msg += " (duration: " + t.sw.String() + ")"
			}
			if msg != "" {
				logrus.Tracef(msg)
			}
		}
	}
	return t
}

// buildMessage builds the message with available information from stack trace
func (t *tracer) buildMessage() string {
	if t.IsNull() {
		return ""
	}

	// Note: this value is very important, it makes sure the internal calls of this package would not interfere with the real caller we want to catch
	//       badly set and you will get a line number that does not match with the one corresponding to the call
	const skipCallers int = 2

	message := t.taskSig
	if _, _, line, ok := runtime.Caller(skipCallers); ok {
		message += " " + t.funcName + t.callerParams + " [" + t.fileName + ":" + strconv.Itoa(line) + "]"
	}
	return message
}

// TraceMessage returns a string containing a trace message
func (t *tracer) TraceMessage(msg ...interface{}) string {
	return "--- " + t.buildMessage() + ": " + strprocess.FormatStrings(msg...)
}

// Trace traces a message
func (t *tracer) Trace(msg ...interface{}) Tracer {
	if !t.IsNull() && t.enabled {
		message := t.TraceMessage(msg...)
		if message != "" {
			logrus.Tracef(message)
		}
	}
	return t
}

// TraceAsError traces a message with error level
func (t *tracer) TraceAsError(msg ...interface{}) Tracer {
	if !t.IsNull() && t.enabled {
		message := t.TraceMessage(msg...)
		if message != "" {
			logrus.Errorf(message)
		}
	}
	return t
}

// TraceCallStack logs the call stack as a trace (displayed only if tracing is enabled)
func (t *tracer) TraceCallStack() Tracer {
	return t.Trace("%s", string(godebug.Stack()))
}

// Stopwatch returns the stopwatch used (if a stopwatch has been asked with WithStopwatch() )
func (t *tracer) Stopwatch() temporal.Stopwatch {
	if t.IsNull() {
		return temporal.NewStopwatch()
	}
	return t.sw
}

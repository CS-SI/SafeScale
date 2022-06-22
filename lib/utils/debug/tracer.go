/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

//go:generate minimock -o mocks/mock_tracer.go -i github.com/CS-SI/SafeScale/v22/lib/utils/debug.Tracer

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
func NewTracer(thing interface{}, enable bool, msg ...interface{}) Tracer {
	if thing == nil {
		return NewTracerFromCtx(context.Background(), enable, msg...)
	}
	switch casted := thing.(type) {
	case context.Context:
		return NewTracerFromCtx(casted, enable, msg...)
	case concurrency.Task:
		return NewTracerFromTask(casted, enable, msg...)
	default:
		return nil
	}
}

// NewTracerFromCtx creates a new Tracer instance
func NewTracerFromCtx(ctx context.Context, enable bool, msg ...interface{}) Tracer {
	t := tracer{
		enabled: enable,
	}

	if aID := ctx.Value(concurrency.KeyForID); aID != nil { // nolint
		var ok bool
		t.taskSig, ok = aID.(string) // nolint
		if !ok {
			nID, _ := uuid.NewV4() //  nolint
			t.taskSig = nID.String()
		}
	} else {
		nID, _ := uuid.NewV4() // nolint
		t.taskSig = nID.String()
	}

	message := strprocess.FormatStrings(msg...)
	if message == "" {
		message = "()"
	}
	t.callerParams = strings.TrimSpace(message)

	if pc, file, _, ok := runtime.Caller(2); ok {
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

// NewTracerFromTask creates a new Tracer instance
func NewTracerFromTask(task concurrency.Task, enable bool, msg ...interface{}) Tracer {
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

	if pc, file, _, ok := runtime.Caller(2); ok {
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
func (instance *tracer) IsNull() bool {
	return instance == nil || (instance.callerParams == "" && (instance.funcName == unknownFunction || instance.fileName == unknownFile))
}

// EnteringMessage returns the content of the message when entering the function
func (instance *tracer) EnteringMessage() string {
	if valid.IsNil(instance) {
		return ""
	}
	return goingInPrefix + instance.buildMessage(0)
}

// WithStopwatch will add a measure of duration between GoingIn and Exiting.
// Exiting will add the elapsed time in the log message (if it has to be logged...).
func (instance *tracer) WithStopwatch() Tracer {
	if instance.sw == nil {
		instance.sw = temporal.NewStopwatch()
	}
	return instance
}

// Entering logs the input message (signifying we are going in) using TRACE level
func (instance *tracer) Entering() Tracer {
	if !valid.IsNil(instance) && !instance.inDone {
		if instance.sw != nil {
			instance.sw.Start()
		}
		if instance.enabled {
			instance.inDone = true
			msg := goingInPrefix + instance.buildMessage(0)
			if msg != "" {
				logrus.Tracef(msg)
			}
		}
	}
	return instance
}

// ExitingMessage returns the content of the message when exiting the function
func (instance *tracer) ExitingMessage() string {
	if valid.IsNil(instance) {
		return ""
	}

	return goingOutPrefix + instance.buildMessage(0)
}

// Exiting logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (instance *tracer) Exiting() Tracer {
	if !valid.IsNil(instance) && !instance.outDone {
		if instance.sw != nil {
			instance.sw.Stop()
		}
		if instance.enabled {
			instance.outDone = true
			msg := goingOutPrefix + instance.buildMessage(0)
			if instance.sw != nil {
				msg += " (duration: " + instance.sw.String() + ")"
			}
			if msg != "" {
				logrus.Tracef(msg)
			}
		}
	}
	return instance
}

// buildMessage builds the message with available information from stack trace
func (instance *tracer) buildMessage(extra uint) string {
	if valid.IsNil(instance) {
		return ""
	}

	// Note: this value is very important, it makes sure the internal calls of this package would not interfere with the real caller we want to catch
	//       badly set, and you will get a line number that does not match with the one corresponding to the call
	skipCallers := 2 + int(extra)

	message := instance.taskSig
	if _, _, line, ok := runtime.Caller(skipCallers); ok {
		message += " " + instance.funcName + instance.callerParams + " [" + instance.fileName + ":" + strconv.Itoa(line) + "]"
	}
	return message
}

// TraceMessage returns a string containing a trace message
func (instance *tracer) TraceMessage(msg ...interface{}) string {
	return "--- " + instance.buildMessage(1) + ": " + strprocess.FormatStrings(msg...)
}

// Trace traces a message
func (instance *tracer) Trace(msg ...interface{}) Tracer {
	if !valid.IsNil(instance) && instance.enabled {
		message := "--- " + instance.buildMessage(0) + ": " + strprocess.FormatStrings(msg...)
		if message != "" {
			logrus.Tracef(message)
		}
	}
	return instance
}

// TraceAsError traces a message with error level
func (instance *tracer) TraceAsError(msg ...interface{}) Tracer {
	if !valid.IsNil(instance) && instance.enabled {
		message := "--- " + instance.buildMessage(0) + ": " + strprocess.FormatStrings(msg...)
		if message != "" {
			logrus.Errorf(message)
		}
	}
	return instance
}

// Stopwatch returns the stopwatch used (if a stopwatch has been asked with WithStopwatch() )
func (instance *tracer) Stopwatch() temporal.Stopwatch {
	if valid.IsNil(instance) {
		return temporal.NewStopwatch()
	}
	return instance.sw
}

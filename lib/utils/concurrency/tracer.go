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

package concurrency

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// Tracer ...
type Tracer struct {
	taskSig      string
	generation   uint
	funcName     string
	inOutMessage string
	enabled      bool
	inDone       bool
	outDone      bool
	sw           *scerr.Stopwatch
}

// NewTracer creates a new Tracer instance
func NewTracer(t Task, message string, enabled bool) *Tracer {
	tracer := Tracer{}
	if t != nil {
		tracer.taskSig = t.GetSignature()
		tracer.generation = t.(*task).generation + 1
	}
	tracer.enabled = enabled

	if message == "" {
		message = "()"
	}

	// Build the message to trace
	if pc, file, line, ok := runtime.Caller(1); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			tracer.funcName = f.Name()
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			tracer.inOutMessage = fmt.Sprintf("%s %s%s [%s:%d]", tracer.taskSig, filepath.Base(tracer.funcName), message, filename, line)
		}
	}

	return &tracer
}

// GoingInMessage returns the content of the message when entering the function
func (t *Tracer) GoingInMessage() string {
	return blockquoteGeneration(t.generation) + ">>>" + t.inOutMessage
}

// WithStopwatch will add a measure of duration between GoingIn and GoingOut.
// GoingOut will add the elapsed time in the log message (if it has to be logged...).
func (t *Tracer) WithStopwatch() *Tracer {
	if t.sw == nil {
		t.sw = &scerr.Stopwatch{}
	}
	return t
}

// GoingIn logs the input message (signifying we are going in) using TRACE level
func (t *Tracer) GoingIn() *Tracer {
	if t.inDone {
		return t
	}
	if t.sw != nil {
		t.sw.Start()
	}
	if t.enabled {
		t.inDone = true
		logrus.Tracef(t.GoingInMessage())
	}
	return t
}

// OnExitTrace returns a function that will log the output message using TRACE level.
func (t *Tracer) OnExitTrace() func() {
	if t.outDone {
		return func() {}
	}
	return func() { t.GoingOut() }
}

// GoingOutMessage returns the content of the message when exiting the function
func (t *Tracer) GoingOutMessage() string {
	return blockquoteGeneration(t.generation) + "<<<" + t.inOutMessage
}

// GoingOut logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (t *Tracer) GoingOut() *Tracer {
	if t.outDone {
		return t
	}
	if t.sw != nil {
		t.sw.Stop()
	}
	if t.enabled {
		t.outDone = true
		msg := t.GoingOutMessage()
		if t.sw != nil {
			msg += " (duration: " + t.sw.String() + ")"
		}
		logrus.Tracef(msg)
	}
	return t
}

// TraceMessage returns a string containing a trace message
func (t *Tracer) TraceMessage(format string, a ...interface{}) string {
	root := fmt.Sprintf(blockquoteGeneration(t.generation)+"---%s %s: ", t.taskSig, t.inOutMessage)
	return root + fmt.Sprintf(format, a...)
}

// Trace traces a message
func (t *Tracer) Trace(format string, a ...interface{}) *Tracer {
	if t.enabled {
		logrus.Tracef(t.TraceMessage(format, a...))
	}
	return t
}

// Stopwatch returns the stopwatch used (if a stopwatch has been asked with WithStopwatch() )
func (t *Tracer) Stopwatch() *scerr.Stopwatch {
	return t.sw
}

// blockquoteGeneration ...
func blockquoteGeneration(generation uint) string {
	const spacing = "  "
	output := ""
	for i := uint(0); i < generation; i++ {
		output += spacing
	}
	return output
}

var removePart atomic.Value

func getPartToRemove() string {
	if anon := removePart.Load(); anon != nil {
		return anon.(string)
	}
	return "github.com/CS-SI/SafeScale/"
}

func init() {
	var rootPath string
	if _, file, _, ok := runtime.Caller(0); ok {
		rootPath = strings.Split(file, "lib/utils")[0]
	}
	removePart.Store(rootPath)
}

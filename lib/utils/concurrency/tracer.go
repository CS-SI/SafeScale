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
}

// NewTracer creates a new Tracer instance
func NewTracer(t Task, message string) *Tracer {
	tracer := Tracer{}
	if t != nil {
		tracer.taskSig = t.GetSignature()
		tracer.generation = t.(*task).generation
	}

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

// Enable enables the traces (if there is something to trace...)
func (t *Tracer) Enable(flag bool) *Tracer {
	if t.inOutMessage == "" {
		// If there is nothing to trace, disable the tracer
		t.enabled = false
	} else {
		t.enabled = flag
	}
	return t
}

// InputMessage returns the content of the message when entering the function
func (t *Tracer) InputMessage() string {
	if t.enabled {
		return blockquoteGeneration(t.generation) + ">>>" + t.inOutMessage
	}
	return ""
}

// In signifies we are going in
func (t *Tracer) In() *Tracer {
	if t.enabled {
		logrus.Tracef(t.InputMessage())
	}
	return t
}

// OutputMessage returns the content of the message when exiting the function
func (t *Tracer) OutputMessage() string {
	if t.enabled {
		return blockquoteGeneration(t.generation) + "<<<" + t.inOutMessage
	}
	return ""
}

// Out signifies we are going out
func (t *Tracer) Out() {
	if t.enabled {
		logrus.Tracef(t.OutputMessage())
	}
}

// Trace traces a message
func (t *Tracer) Trace(message string) {
	if t.enabled {
		logrus.Tracef(blockquoteGeneration(t.generation)+"---%s %s %s", t.taskSig, t.inOutMessage, message)
	}
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

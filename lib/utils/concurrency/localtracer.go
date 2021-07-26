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

package concurrency

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

// tracer ...
type tracer struct {
	taskSig      string
	fileName     string
	funcName     string
	callerParams string
	enabled      bool
	inDone       bool
	outDone      bool
}

const (
	unknownFunction string = "<unknown function>"
	unknownFile     string = "<unknown file>"
	enteringPrefix  string = ">>> "
	exitingPrefix   string = "<<< "
	messagePrefix   string = "--- "
)

// newTracer creates a new tracer instance
func newTracer(task Task, enabled bool) *tracer {
	t := tracer{
		taskSig: task.Signature(),
		enabled: enabled,
	}

	t.callerParams = "()"

	if pc, file, _, ok := runtime.Caller(1); ok {
		t.fileName = strings.Replace(file, getPartToRemove(), "", 1)
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

// isNull returns true if the instance is a null value of tracer
func (t *tracer) isNull() bool {
	return t == nil || (t.callerParams == "" && (t.funcName == unknownFunction || t.fileName == unknownFile))
}

// entering logs the input message (signifying we are going in) using TRACE level
func (t *tracer) entering() *tracer {
	if !t.isNull() && !t.inDone {
		if t.enabled {
			t.inDone = true
			logrus.Tracef(enteringPrefix + t.buildMessage())
		}
	}
	return t
}

// exiting logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (t *tracer) exiting() *tracer {
	if !t.isNull() && !t.outDone {
		if t.enabled {
			t.outDone = true
			logrus.Tracef(exitingPrefix + t.buildMessage())
		}
	}
	return t
}

// buildMessage builds the message with available information from stack trace
func (t *tracer) buildMessage() string {
	if t.isNull() {
		return ""
	}

	message := t.taskSig
	if _, _, line, ok := runtime.Caller(1); ok {
		message += " " + t.funcName + t.callerParams + " [" + t.fileName + ":" + strconv.Itoa(line) + "]"
	}
	return message
}

// Trace traces a message
func (t *tracer) trace(msg ...interface{}) *tracer {
	if !t.isNull() && t.enabled {
		fmt.Println(messagePrefix + t.buildMessage() + ": " + strprocess.FormatStrings(msg...))
	}
	return t
}

// removePart contains the basedir to remove from file pathes
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

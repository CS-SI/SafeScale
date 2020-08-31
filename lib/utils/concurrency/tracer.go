/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
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
    unknownFunction = "<unknown function>"
    unknownFile     = "<unknown file>"
)

// newTracer creates a new tracer instance
func newTracer(t Task, enabled bool) *tracer {
    tracer := tracer{}
    if t != nil {
        tracer.taskSig = t.GetSignature()
    }
    tracer.enabled = enabled

    tracer.callerParams = "()"

    if pc, file, _, ok := runtime.Caller(1); ok {
        tracer.fileName = strings.Replace(file, getPartToRemove(), "", 1)
        if f := runtime.FuncForPC(pc); f != nil {
            tracer.funcName = filepath.Base(f.Name())
        }
    }
    if tracer.funcName == "" {
        tracer.funcName = unknownFunction
    }
    if tracer.fileName == "" {
        tracer.funcName = unknownFile
    }

    return &tracer
}

// isNull returns true if the instance is a null value of tracer
func (t *tracer) isNull() bool {
    return t == nil || (t.callerParams == "" && (t.funcName == unknownFunction || t.fileName == unknownFile))
}

// GoingInMessage returns the content of the message when entering the function
func (t *tracer) goingInMessage() string {
    if t.isNull() {
        return ""
    }
    return ">>> " + t.buildMessage()
}

// GoingIn logs the input message (signifying we are going in) using TRACE level
func (t *tracer) goingIn() *tracer {
    if !t.isNull() && !t.inDone {
        if t.enabled {
            t.inDone = true
            msg := t.goingInMessage()
            if msg != "" {
                logrus.Tracef(msg)
            }
        }
    }
    return t
}

// goingOutMessage returns the content of the message when exiting the function
func (t *tracer) goingOutMessage() string {
    if t.isNull() {
        return ""
    }
    return "<<< " + t.buildMessage()
}

// GoingOut logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (t *tracer) goingOut() *tracer {
    if !t.isNull() && !t.outDone {
        if t.enabled {
            t.outDone = true
            msg := t.goingOutMessage()
            if msg != "" {
                logrus.Tracef(msg)
            }
        }
    }
    return t
}

// OnExitTrace returns a function that will log the output message using TRACE level.
func (t *tracer) onExitTrace() func() {
    if t.isNull() || t.outDone {
        return func() {}
    }
    return func() { t.goingOut() }
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

// TraceMessage returns a string containing a trace message
func (t *tracer) traceMessage(format string, a ...interface{}) string {
    return "--- " + t.buildMessage() + ": " + fmt.Sprintf(format, a...)
}

// Trace traces a message
func (t *tracer) trace(format string, a ...interface{}) *tracer {
    if !t.isNull() && t.enabled {
        msg := t.traceMessage(format, a...)
        if msg != "" {
            logrus.Tracef(msg)
        }
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

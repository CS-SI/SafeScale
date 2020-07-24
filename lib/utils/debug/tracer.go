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

package debug

import (
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "sync/atomic"

    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Tracer ...
type Tracer interface {
    WithStopwatch() Tracer
    GoingInMessage() string
    GoingIn() Tracer
    GoingOutMessage() string
    GoingOut() Tracer
    OnExitTrace() func()
    TraceMessage(format string, a ...interface{}) string
    Trace(format string, a ...interface{}) Tracer
    TraceAsError(format string, a ...interface{}) Tracer
    Stopwatch() temporal.Stopwatch
}

// IsLogActive ... FIXME:
func IsLogActive(key string) bool {
    if logs := os.Getenv("SAFESCALE_OPTIONAL_LOGS"); logs != "" {
        return strings.Contains(logs, key)
    }
    return false
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
    unknownFunction = "<unknown function>"
    unknownFile = "<unknown file>"
)

// NewTracer creates a new tracer instance
func NewTracer(t concurrency.Task, message string, enabled bool) *tracer {
    tracer := tracer{}
    if t != nil {
        tracer.taskSig = t.GetSignature()
    }
    tracer.enabled = enabled

    tracer.callerParams = strings.TrimSpace(message)
    if message == "" {
        tracer.callerParams = "()"
    }

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

// IsNull returns true if the instance is a null value of tracer
func (t *tracer) IsNull() bool {
    return t == nil || (t.callerParams == "" && (t.funcName == unknownFunction || t.fileName == unknownFile))
}

// WithStopwatch will add a measure of duration between GoingIn and GoingOut.
// GoingOut will add the elapsed time in the log message (if it has to be logged...).
func (t *tracer) WithStopwatch() *tracer {
    if !t.IsNull() && t.sw == nil {
        t.sw = temporal.NewStopwatch()
    }
    return t
}

// GoingInMessage returns the content of the message when entering the function
func (t *tracer) GoingInMessage() string {
    if t.IsNull() {
        return ""
    }
    return ">>> " + t.buildMessage()
}

// GoingIn logs the input message (signifying we are going in) using TRACE level
func (t *tracer) GoingIn() *tracer {
    if !t.IsNull() && !t.inDone {
        if t.sw != nil {
            t.sw.Start()
        }
        if t.enabled {
            t.inDone = true
            msg := t.GoingInMessage()
            if msg != "" {
                logrus.Tracef(msg)
            }
        }
    }
    return t
}

// GoingOutMessage returns the content of the message when exiting the function
func (t *tracer) GoingOutMessage() string {
    if t.IsNull() {
        return ""
    }
    return "<<< " + t.buildMessage()
}

// GoingOut logs the output message (signifying we are going out) using TRACE level and adds duration if WithStopwatch() has been called.
func (t *tracer) GoingOut() *tracer {
    if !t.IsNull() && !t.outDone {
        if t.sw != nil {
            t.sw.Stop()
        }
        if t.enabled {
            t.outDone = true
            msg := t.GoingOutMessage()
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

// OnExitTrace returns a function that will log the output message using TRACE level.
func (t *tracer) OnExitTrace() func() {
    if t.IsNull() || t.outDone {
        return func() {}
    }
    return func() { t.GoingOut() }
}

// buildMessage builds the message with available information from stack trace
func (t *tracer) buildMessage() string {
    if t.IsNull() {
        return ""
    }

    message := t.taskSig
    if _, _, line, ok := runtime.Caller(1); ok {
        message += " " + t.funcName + t.callerParams + " [" + t.fileName + ":" + strconv.Itoa(line) + "]"
    }
    return message
}

// TraceMessage returns a string containing a trace message
func (t *tracer) TraceMessage(format string, a ...interface{}) string {
    return "--- " + t.buildMessage() + ": " + fmt.Sprintf(format, a...)
}

// Trace traces a message
func (t *tracer) Trace(format string, a ...interface{}) *tracer {
    if !t.IsNull() && t.enabled {
        msg := t.TraceMessage(format, a...)
        if msg != "" {
            logrus.Tracef(msg)
        }
    }
    return t
}

// TraceAsError traces a message with error level
func (t *tracer) TraceAsError(format string, a ...interface{}) *tracer {
    if !t.IsNull() && t.enabled {
        msg := t.TraceMessage(format, a...)
        if msg != "" {
            logrus.Errorf(msg)
        }
    }
    return t
}

// Stopwatch returns the stopwatch used (if a stopwatch has been asked with WithStopwatch() )
func (t *tracer) Stopwatch() temporal.Stopwatch {
    return t.sw
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

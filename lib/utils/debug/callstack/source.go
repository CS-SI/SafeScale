/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package callstack

import (
    "bufio"
    "fmt"
    "path/filepath"
    "reflect"
    "runtime"
    godebug "runtime/debug"
    "strings"
    "sync/atomic"

    srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
)


var sourceFileRemovePart atomic.Value

// DecorateWith adds call trace to the message "prefix what: why"
// 'ignoreCount' indicates the number of call that have to be ignored at the beginning of the stack trace
func DecorateWith(prefix, what, why string, ignoreCount int) string {
    const missingPrefixMessage = "uncategorized error occurred:"

    msg := prefix
    if prefix == "" {
        msg = missingPrefixMessage
    }

    if what != "" {
        msg += " '" + what + "'"
    }

    if ignoreCount < 2 {
        ignoreCount = 2
    }

    if pc, file, line, ok := runtime.Caller(ignoreCount); ok {
        if f := runtime.FuncForPC(pc); f != nil {
            filename := strings.Replace(file, SourceFilePrefixToRemove(), "", 1)
            if what == "" {
                msg += fmt.Sprintf(" %s", filepath.Base(f.Name()))
            } else {
                msg += fmt.Sprintf(" in %s", filepath.Base(f.Name()))
            }
            if why != "" {
                msg += ": " + why
            }
            msg += fmt.Sprintf(" [%s:%d]", filename, line)
        }
    } else {
        if why != "" {
            msg += ": " + why
        }
    }
    msg += "\n" + string(IgnoreTraceUntil(godebug.Stack(), "SafeScale/lib/utils/debug/callstack/callstack", FirstOccurence))
    return msg
}

// Occurence defines at what occurence of search IgnoreTraceUntil() will stop
type Occurence bool
const (
    FirstOccurence Occurence = false
    LastOccurence Occurence = true
)

// IgnoreTraceUntil cuts all the lines of the trace before and including lines with 'search' in it
// if 'stop' contains FirstOccurence, cuts until the first occurence of line containing 'search'
// if 'stop' contains LastOccurence, cuts until the last occurence of line containing 'search'
func IgnoreTraceUntil(callTrace interface{}, search string, stop Occurence) string {
    if callTrace == nil {
        return ""
    }

    var source string
    switch casted := callTrace.(type) {
    case []uint8:
        source = string(casted)
    case string:
        source = casted
    default:
        return fmt.Sprintf("do not known how to handle calltrace type '%s'", reflect.TypeOf(callTrace).String())
    }

    if search == "" {
        return source
    }

    var (
        buffer string
        goroutine string
        found bool
    )
    scanner := bufio.NewScanner(strings.NewReader(source))
    if !scanner.Scan() {
        return ""
    }
    goroutine = scanner.Text()+"\n"

    changeSourcePath := SourceFilePathUpdater()
    for scanner.Scan() {
        line := scanner.Text()
        if (stop == LastOccurence || !found) && strings.Contains(line, search) {
            buffer = ""
            found = true
            continue
        }
        buffer += changeSourcePath(line) + "\n"
    }
    return goroutine+buffer
}

// SourceFilePathUpdater returns a function to alter source file path, if debug is not enabled
func SourceFilePathUpdater() func(string) string {
    var (
        fn func(string) string
    )
    if srvutils.Debug {
        // Do not change anything in source file path
        fn = func(path string) string { return path }
    } else {
        // Alter filepath to remove absolute part (that may not exist)
        removePath := SourceFilePrefixToRemove()
        fn = func(path string) string {
            return strings.Replace(path, removePath, "", 1)
        }
    }
    return fn
}

const (
    defaultPartToRemove = "go/src/github.com/CS-SI/SafeScale/"
    sourceFileSearchString = "github.com/CS-SI/SafeScale/"
)

// SourceFilePrefixToRemove returns the part of the file path to remove before display.
func SourceFilePrefixToRemove() string {
    if anon := sourceFileRemovePart.Load(); anon != nil {
        return anon.(string)
    }
    return defaultPartToRemove
}

func init() {
    var rootPath string
    if _, f, _, ok := runtime.Caller(0); ok {
        rootPath = strings.TrimRight(strings.Split(f, sourceFileSearchString)[0], "/")
        rootPath = filepath.Dir(filepath.Dir(rootPath))
    }
    sourceFileRemovePart.Store(rootPath)
}

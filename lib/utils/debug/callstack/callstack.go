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

package callstack

import (
	"bufio"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	godebug "runtime/debug"
	"strings"
)

// DecorateWith adds call trace to the message "prefix what: why"
// 'ignoreCount' indicates the number of call that have to be ignored at the beginning of the stack trace
func DecorateWith(prefix, what, why string, ignoreCount uint) string {
	const missingPrefixMessage = "uncategorized error occurred:"

	msg := prefix
	if prefix == "" {
		msg = missingPrefixMessage
	}

	if what != "" {
		msg += what
	}

	if ignoreCount < 2 {
		ignoreCount = 2
	}

	if pc, file, line, ok := runtime.Caller(int(ignoreCount)); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, sourceFilePrefixToRemove(), "", 1)
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
	msg += "\n" + IgnoreTraceUntil(godebug.Stack(), "SafeScale/lib/utils/debug/callstack/callstack", FirstOccurrence)
	return msg
}

// Occurrence defines at what occurrence of search IgnoreTraceUntil() will stop
type Occurrence bool

const (
	FirstOccurrence Occurrence = false

	LastOccurrence Occurrence = true
)

// IgnoreTraceUntil cuts all the lines of the trace before and including lines with 'search' in it
// if 'stop' contains FirstOccurrence, cuts until the first occurrence of line containing 'search'
// if 'stop' contains LastOccurrence, cuts until the last occurrence of line containing 'search'
func IgnoreTraceUntil(callTrace interface{}, search string, stop Occurrence) string {
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
		return fmt.Sprintf("do not known how to handle calltrace type '%s': %v", reflect.TypeOf(callTrace).String(), callTrace)
	}

	if search == "" {
		return source
	}

	var (
		buffer    string
		goroutine string
		found     bool
	)
	scanner := bufio.NewScanner(strings.NewReader(source))
	if !scanner.Scan() {
		return ""
	}
	goroutine = scanner.Text() + "\n"

	changeSourcePathFunc := SourceFilePathUpdater()
	for scanner.Scan() {
		line := scanner.Text()
		if stop == LastOccurrence && strings.Contains(line, search) {
			buffer = ""
			found = true
			continue
		} else if !found && stop == FirstOccurrence && strings.Contains(line, search) {
			buffer = ""
			found = true
			continue
		}
		buffer += changeSourcePathFunc(line) + "\n"
	}

	return goroutine + buffer
}

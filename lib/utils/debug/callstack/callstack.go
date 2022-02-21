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

package callstack

import (
	"bufio"
	"fmt"
	"reflect"
	"runtime"
	godebug "runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"
)

type call struct {
	fn   string
	file string
}

// DecorateWith adds call trace to the message "prefix what: why"
// 'ignoreCount' indicates the number of call that have to be ignored at the beginning of the stack trace
func DecorateWith(prefix, what, why string, ignoreCount uint) string {
	const separator = ": "
	const missingPrefixMessage = "uncategorized error occurred"

	var fragments []string

	if prefix != "" {
		fragments = append(fragments, prefix)
	} else {
		fragments = append(fragments, missingPrefixMessage)
	}

	fragments = append(fragments, what)

	recovered, err := getStack(godebug.Stack(), "/src/runtime", LastOccurrence)
	if err != nil {
		logrus.Warnf("unable to get stack trace: %v", err)
		return ""
	}
	if len(recovered) > 0 {
		for {
			if len(recovered) == 0 {
				break
			}
			lin := recovered[len(recovered)-1]
			if strings.Contains(lin.file, "src/testing/testing") {
				if len(recovered) < 2 {
					break
				}
				recovered = recovered[0 : len(recovered)-2]
			} else {
				break
			}
		}
	}

	if len(recovered) == 0 {
		logrus.Warnf("unable to filter stack trace")
		return ""
	}

	last := recovered[len(recovered)-1]

	whatToRemove := sourceFilePrefixToRemove()
	last.file = strings.Replace(last.file, whatToRemove, "", 1)

	fragments = append(fragments, fmt.Sprintf("in function %s", last.fn))
	fragments = append(fragments, why)

	lin := strings.LastIndex(last.file, " ")
	if lin != -1 {
		last.file = last.file[0:lin]
	}

	fragments = append(fragments, fmt.Sprintf(" [%s]", strings.TrimSpace(last.file)))
	fragments = append(fragments, "\n")
	fragments = append(fragments, IgnoreTraceUntil(godebug.Stack(), "src/runtime/panic", LastOccurrence))

	var cleaned []string
	for _, ct := range fragments {
		if ct != "" {
			cleaned = append(cleaned, ct)
		}
	}

	msg := strings.Join(cleaned, separator)
	return msg
}

func getStack(callTrace interface{}, search string, stop Enum) ([]call, error) {
	if callTrace == nil {
		callTrace = godebug.Stack()
	}

	var calls []call

	isRt := false
	var source string
	switch casted := callTrace.(type) {
	case []uint8:
		source = string(casted)
	case string:
		source = casted
	case runtime.Error:
		source = casted.Error()
		isRt = true
	default:
		return nil, fmt.Errorf("invalid type")
	}

	if isRt {
		search = "src/runtime"
	}

	scanner := bufio.NewScanner(strings.NewReader(source))
	if !scanner.Scan() {
		return calls, fmt.Errorf("empty buffer")
	}
	_ = scanner.Text()
	changeSourcePathFunc := SourceFilePathUpdater()

	if stop == FirstOccurrence {
		found := false

		for scanner.Scan() {
			line := scanner.Text()
			scanner.Scan()
			nextline := changeSourcePathFunc(scanner.Text())
			calls = append(calls, call{
				fn:   line,
				file: nextline,
			})
			if found {
				break
			}
			if strings.Contains(nextline, search) {
				found = true
			}
		}

		return calls, nil
	}

	found := 0
	lastIndex := 0

	for scanner.Scan() {
		line := scanner.Text()
		scanner.Scan()
		nextline := changeSourcePathFunc(scanner.Text())
		calls = append(calls, call{
			fn:   line,
			file: nextline,
		})
		if strings.Contains(nextline, search) {
			found++
			lastIndex = len(calls)
		}
	}

	if found > 1 {
		if lastIndex+1 < len(calls) {
			calls = calls[0 : lastIndex+1]
		}
	}

	return calls, nil
}

// IgnoreTraceUntil cuts all the lines of the trace before and including lines with 'search' in it
// if 'stop' contains FirstOccurrence, cuts until the first occurrence of line containing 'search'
// if 'stop' contains LastOccurrence, cuts until the last occurrence of line containing 'search'
func IgnoreTraceUntil(callTrace interface{}, search string, stop Enum) string {
	if callTrace == nil {
		return ""
	}

	isRt := false
	var source string
	switch casted := callTrace.(type) {
	case []uint8:
		source = string(casted)
	case string:
		source = casted
	case runtime.Error:
		source = casted.Error()
		isRt = true
	default:
		return fmt.Sprintf("do not known how to handle calltrace type '%s': %v", reflect.TypeOf(callTrace).String(), callTrace)
	}

	if search == "" {
		return source
	}

	if isRt {
		search = "src/runtime"
	}

	var (
		buffer    string
		goroutine string
	)
	scanner := bufio.NewScanner(strings.NewReader(source))
	if !scanner.Scan() {
		return ""
	}
	goroutine = scanner.Text() + "\n"

	var calls []call

	changeSourcePathFunc := SourceFilePathUpdater()

	if stop == FirstOccurrence {
		found := false

		for scanner.Scan() {
			line := scanner.Text()
			scanner.Scan()
			nextline := changeSourcePathFunc(scanner.Text())
			calls = append(calls, call{
				fn:   line,
				file: nextline,
			})
			if found {
				break
			}
			if strings.Contains(nextline, search) {
				found = true
			}
		}

		for _, item := range calls {
			buffer += item.fn + item.file
		}

		return goroutine + buffer
	}

	found := 0
	lastIndex := 0

	for scanner.Scan() {
		line := scanner.Text()
		scanner.Scan()
		nextline := changeSourcePathFunc(scanner.Text())
		calls = append(calls, call{
			fn:   line,
			file: nextline,
		})
		if strings.Contains(nextline, search) {
			found++
			lastIndex = len(calls)
		}
	}

	if found > 1 {
		if lastIndex+1 < len(calls) {
			calls = calls[0 : lastIndex+1]
		}
	}

	for _, item := range calls {
		buffer += item.fn + item.file
	}

	return goroutine + buffer
}

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

package debug

import (
	"fmt"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

// DecorateWithCallTrace adds call trace to the message "prefix what: why"
func DecorateWithCallTrace(prefix, what, why string) string {
	const missingPrefixMessage = "uncategorized error occurred:"

	msg := prefix
	if prefix == "" {
		msg = missingPrefixMessage
	}

	if what != "" {
		msg += " '" + what + "'"
	}

	if pc, file, line, ok := runtime.Caller(2); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, SourceFilePartToRemove(), "", 1)
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
	msg += "\n" + string(debug.Stack())
	return msg
}

// SourceFilePartToRemove returns the part of the file path to remove before display.
func SourceFilePartToRemove() string {
	if anon := sourceFileRemovePart.Load(); anon != nil {
		return anon.(string)
	}
	return "github.com/CS-SI/SafeScale/"
}

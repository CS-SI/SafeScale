//go:build !generics
// +build !generics

/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package strprocess

import (
	"fmt"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Plural returns 's' if value > 1, "" otherwise
func Plural(value uint) string {
	if value > 1 {
		return "s"
	}
	return ""
}

// Capitalize makes the first letter of the first word uppercased
func Capitalize(value string) string {
	fields := strings.Fields(value)
	if len(fields) > 0 {
		// WORKAROUND: cases.Title(language.Und, cases.NoLower).String consider ' as the beginning of a new word, so "can't" becomes "Can'T"...
		quoted := strings.Split(fields[0], "'")
		if len(quoted) > 1 {
			quoted[0] = cases.Title(language.Und, cases.NoLower).String(quoted[0])
			fields[0] = strings.Join(quoted, "'")
		} else {
			fields[0] = cases.Title(language.Und, cases.NoLower).String(fields[0])
		}
	}
	return strings.Join(fields, " ")
}

// FormatStrings formats the strings passed as parameters, using first one as format specifier for fmt.Sprintf if
// there are more than 1 string.
func FormatStrings(msg ...interface{}) string {
	if msg == nil {
		return ""
	}

	l := len(msg)
	if l == 0 {
		return ""
	}
	if len(msg) > 1 {
		if _, ok := msg[0].(string); ok {
			return fmt.Sprintf(msg[0].(string), msg[1:]...)
		}

		return ""
	}

	if msg[0] == nil {
		return ""
	}

	if _, ok := msg[0].(string); !ok {
		return ""
	}

	// return fmt.Sprint(msg[0].(string))
	return msg[0].(string)
}

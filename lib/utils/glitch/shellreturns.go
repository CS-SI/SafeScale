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

package glitch

import (
	"fmt"
	"strings"
)

// ReturnedValuesFromShellToError builds an error composed of returned values (return code, stdout, stderr) of a shell command
func ReturnedValuesFromShellToError(retcode int, stdout string, stderr string, err error, msg string) error {
	if retcode == 0 {
		return nil
	}

	var collected []string
	if stdout != "" {
		errLines := strings.Split(stdout, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}
	if stderr != "" {
		errLines := strings.Split(stderr, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}

	if len(collected) > 0 {
		if err != nil {
			return Wrap(err, fmt.Sprintf("%s: std error [%s]", msg, collected))
		}
		return NewError("%s: std error [%s]", msg, strings.Join(collected, ";"))
	}

	return nil
}

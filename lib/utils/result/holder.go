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

package result

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/utils/result/result.Result -o mocks/mock_result.go

// Holder ...
type Holder[T any] interface {
	Successful() (bool, fail.Error)
	Completed() (bool, fail.Error)
	Error() (error, fail.Error)
	ErrorMessage() (string, fail.Error)
}

// holder[T any] implements Holder interface
type holder[T any] struct {
	err       error // if an error occurred, 'err' contains it
	payload   T     // contains the real holder
	completed bool  // if true, the script has been run to completion
	success   bool  // if true, the script has finished, and the holder is a success
	frozen    bool  // if true, cannot update the holder anymore
}

// NewHolder creates a new instance of Holder with payload of type T
func NewHolder[T any](opts ...Option[T]) (*holder[T], fail.Error) {
	out := &holder[T]{}
	return out, out.Update(opts...)
}

// Update allows to update content of the holder
func (r *holder[T]) Update(opts ...Option[T]) fail.Error {
	if valid.IsNull(r) {
		return fail.InvalidInstanceError()
	}

	if r.frozen {
		return fail.InvalidRequestError("cannot update a holder already locked")
	}

	for _, v := range opts {
		xerr := v(r)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// IsLocked tells if the Holder is locked (ie nothing can be updated anymore)
func (r *holder[T]) IsLocked() bool {
	if valid.IsNull(r) {
		return false
	}

	return r.frozen
}

// Successful returns true if the script has finished AND its resultGroup is a success
func (r *holder[T]) Successful() (bool, fail.Error) {
	if valid.IsNull(r) {
		return false, fail.InvalidInstanceError()
	}

	return r.success, nil
}

// Completed returns true if the script has finished, false otherwise
func (r *holder[T]) Completed() (bool, fail.Error) {
	if valid.IsNull(r) {
		return false, fail.InvalidInstanceError()
	}

	return r.completed, nil
}

func (r *holder[T]) Error() (error, fail.Error) {
	if valid.IsNull(r) {
		return nil, fail.InvalidInstanceError()
	}

	return r.err, nil
}

func (r *holder[T]) ErrorMessage() (string, fail.Error) {
	if valid.IsNull(r) {
		return "", fail.InvalidInstanceError()
	}

	var msg string
	if r.err != nil {
		msg = r.err.Error()
	}
	if msg == "" && r.err != nil {
		switch casterr := r.err.(type) {
		case *fail.ErrExecution:
			var (
				retcode        int
				stdout, stderr string
			)
			if anon, ok := casterr.Annotation("retcode"); ok {
				retcode = anon.(int)
			}
			if anon, ok := casterr.Annotation("stdout"); ok {
				stdout = anon.(string)
			}
			if anon, ok := casterr.Annotation("stderr"); ok {
				stderr = anon.(string)
			}
			recoveredErr := ""
			output := stdout
			if len(output) > 0 {
				output += "\n"
			}
			output += stderr
			if len(output) > 0 {
				lastMsg := ""
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					if strings.Contains(line, "+ echo '") {
						lastMsg = line
					}
				}

				if len(lastMsg) > 0 {
					recoveredErr = lastMsg[8 : len(lastMsg)-1]
				}
			}

			if len(recoveredErr) > 0 {
				msg = fmt.Sprintf("exited with error code %d: %s", retcode, recoveredErr)
			} else {
				msg = fmt.Sprintf("exited with error code %d", retcode)
			}

		default:
			msg = r.err.Error()
		}
	}
	return msg, nil
}

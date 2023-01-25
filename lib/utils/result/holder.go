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

package result

import (
	"fmt"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/utils/result.Holder -o mocks/mock_holder.go

// Holder ...
type Holder[T any] interface {
	Error() error
	ErrorMessage() string
	IsCompleted() bool
	IsFrozen() bool
	IsSuccessful() bool
	TagCompletedFromError(error) error
	TagSuccessFromCondition(bool) error
	Payload() T
}

// holder[T any] implements Holder interface
type holder[T any] struct {
	mu        *sync.Mutex
	err       error // if an error occurred, 'err' contains it
	payload   T     // contains the real holder
	completed bool  // if true, the script has been run to completion
	success   bool  // if true, the script has finished, and the holder is a success
	frozen    bool  // if true, cannot update the holder anymore
}

// NewHolder creates a new instance of Holder with payload of type T
func NewHolder[T any](opts ...Option[T]) (*holder[T], fail.Error) {
	out := &holder[T]{mu: &sync.Mutex{}}
	return out, fail.Wrap(out.Update(opts...))
}

// Update allows to update content of the holder
func (r *holder[T]) Update(opts ...Option[T]) error {
	if valid.IsNull(r) {
		return fail.InvalidInstanceError()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fail.InvalidRequestError("failed to change state of Holder because it is frozen")
	}

	for _, v := range opts {
		xerr := v(r)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// TagSuccessFromCondition ...
func (r *holder[T]) TagSuccessFromCondition(b bool) error {
	return r.Update(TagSuccessFromCondition[T](b))
}

// TagCompletedFromError marks the holder as completed if err == nil
func (r *holder[T]) TagCompletedFromError(err error) error {
	return r.Update(TagCompletedFromError[T](err))
}

// TagFrozen ...
func (r *holder[T]) TagFrozen() error {
	return r.Update(TagFrozen[T]())
}

// IsFrozen tells if the Holder is locked (ie nothing can be updated anymore)
func (r *holder[T]) IsFrozen() bool {
	if valid.IsNull(r) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.frozen
}

// IsSuccessful returns true if the script has finished AND its group is a success
func (r *holder[T]) IsSuccessful() bool {
	if valid.IsNull(r) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.success
}

// IsCompleted returns true if the script has finished, false otherwise
func (r *holder[T]) IsCompleted() bool {
	if valid.IsNull(r) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.completed
}

func (r *holder[T]) Error() error {
	if valid.IsNull(r) {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.err
}

func (r *holder[T]) ErrorMessage() string {
	if valid.IsNull(r) {
		return ""
	}

	r.mu.Lock()
	defer r.mu.Unlock()

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
				retcode, ok = anon.(int)
				if !ok {
					_ = casterr.AddConsequence(fail.InconsistentError("failed to cast 'retcode' to int"))
				}
			}
			if anon, ok := casterr.Annotation("stdout"); ok {
				stdout, ok = anon.(string)
				if !ok {
					_ = casterr.AddConsequence(fail.InconsistentError("failed to cast 'stdout' to string"))
				}
			}
			if anon, ok := casterr.Annotation("stderr"); ok {
				stderr, ok = anon.(string)
				if !ok {
					_ = casterr.AddConsequence(fail.InconsistentError("failed to cast 'stderr' to string"))
				}
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
	return msg
}

// Payload returns the data carried by the Holder, if result is completed
func (r *holder[T]) Payload() T {
	empty := new(T)

	if r.IsCompleted() {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.payload
	}

	return *empty
}

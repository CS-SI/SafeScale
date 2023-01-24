//go:build alltests
// +build alltests

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

package concurrency

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkTestAbortByChannels(b *testing.B) {
	failed := false
	growing := 600
	tunit := time.Microsecond
	for i := 0; i < 14500; i++ {
		var botched error
		timeOut := make(chan struct{})
		stopper := make(chan struct{})
		otherstopper := make(chan struct{})
		cleanup := make(chan struct{})

		basis := time.Duration(50)
		delta := time.Duration(growing)

		time.AfterFunc(basis*tunit, func() { // Scheduled cancel after 50 microsec
			go func() {
				otherstopper <- struct{}{}
				close(otherstopper)
				close(stopper)
			}()

			go func() {
				time.Sleep(delta * tunit) // Scheduled timeout 200 microsec after -> 200 MICROsec is more than enough
				timeOut <- struct{}{}
				close(timeOut)
				close(stopper) // Even if we fail we have to trigger the cleanup
			}()
		})

		go func() {
		out:
			for {
				time.Sleep(2000 * tunit) // #Fake work of 20 microseconds at each iteration
				select {                 // Check with default it's like checking Abort() function, only when stopper is closed we take the case
				case <-stopper:
					cleanup <- struct{}{}
					close(cleanup)
					break out // a return will also do the trick
				default:
					continue
				}
			}
		}()

		select {
		case <-otherstopper: // cancel got here 1st as it should
			botched = nil
		case <-timeOut: // that should never happen (unless overhead introduced by goroutine scheduler, like when setting tunit to 1 nanosecond)
			botched = fmt.Errorf("IT FAILED")
		}

		select {
		case <-cleanup:

		}

		if botched != nil {
			// b.Errorf(botched.Error())
			// break
			growing = growing + 50
			failed = true
		}
	}

	if failed {
		b.Errorf("The last value was: %s", time.Duration(growing)*tunit)
	}
}

func BenchmarkTestAlternativeAbortByChannels(b *testing.B) {
	failed := false
	growing := 350
	tunit := time.Microsecond

	for i := 0; i < 14500; i++ {
		var botched error

		timeOut := make(chan struct{})
		stopper := make(chan struct{})
		cleanup := make(chan struct{})
		nomorework := make(chan struct{})

		basis := time.Duration(50)
		delta := time.Duration(growing)

		time.AfterFunc(basis*tunit, func() {
			go func() {
				time.Sleep(delta * tunit)
				timeOut <- struct{}{}
				close(timeOut)
				close(nomorework)
			}()
			go func() {
				stopper <- struct{}{}
				close(stopper)
				close(nomorework)
			}()
		})

		go func() {
			done := make(chan struct{})
			go func() {
				for {
					time.Sleep(2000 * tunit)
					select {
					case <-nomorework: // when this is closed, we break the for, it never blocks because of the default
						done <- struct{}{}
						close(done)
						return
					default:
					}
				}
			}()

			select {
			case <-done:

			}

			cleanup <- struct{}{}
			close(cleanup)
		}()

		select {
		case <-stopper:
			botched = nil
		case <-timeOut:
			botched = fmt.Errorf("IT FAILED")
		}

		select {
		case <-cleanup:

		}

		if botched != nil {
			growing = growing + 50
			failed = true
		}
	}

	if failed {
		b.Errorf("The last value was: %s", time.Duration(growing)*tunit)
	}
}

func BenchmarkTestAlternativeAbortByCtxCancel(b *testing.B) {
	failed := false
	growing := 250
	tunit := time.Microsecond
	for i := 0; i < 14500; i++ {
		failed = false
		var botched error

		cleanup := make(chan struct{})

		// context is more elegant and requires less boilerplate, but it has a cost: in previous functions, delta
		// has a value of 1 microsecond and still works, here we require 1200 microseconds to pass reliably the test
		basis := time.Duration(50)
		delta := time.Duration(growing)

		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, (basis+delta)*tunit)
		defer cancel()

		time.AfterFunc(basis*tunit, func() {
			cancel()
		})

		go func() {
			done := make(chan struct{})
			go func() {
				for {
					time.Sleep(2000 * tunit)
					select {
					case <-ctxWithTimeout.Done(): // when this is closed, we break the for, it never blocks because of the default
						done <- struct{}{}
						return
					}
				}
			}()

			select {
			case <-done:

			}

			cleanup <- struct{}{}
		}()

		select {
		case <-ctxWithTimeout.Done():
			botched = ctxWithTimeout.Err()
		}

		select {
		case <-cleanup:

		}

		if botched != nil {
			if botched == context.DeadlineExceeded {
				// b.Errorf(botched.Error())
				growing = growing + 50
				failed = true
			}
		}
	}

	if failed {
		b.Errorf("The last value was: %s", time.Duration(growing)*tunit)
	}
}

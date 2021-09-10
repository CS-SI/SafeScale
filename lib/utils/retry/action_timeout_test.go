/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package retry

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func randomErrGen() (string, int, error) {
	ladder := rand.Intn(9)
	fmt.Println(ladder)
	switch ladder {
	case 0:
		return "working", 302, nil
	case 1:
		return "", 404, fmt.Errorf("error %d", 404)
	case 2:
		return "", 500, fmt.Errorf("error %d", 500)
	case 3:
		return "", 202, fmt.Errorf("error %d", 202)
	case 4:
		return "", 666, nil
	case 5:
		fmt.Println("Taking a nap")
		time.Sleep(30 * time.Millisecond)
		return "working late", 302, nil
	case 6:
		fmt.Println("Taking a nap with failure")
		time.Sleep(30 * time.Millisecond)
		return "", 667, fmt.Errorf("error %d", 667)
	default:
		return "somehow working", 300 + rand.Intn(5), nil
	}
}

func TestStraight(t *testing.T) {
	retryErr := WhileUnsuccessful(
		func() error {
			time.Sleep(30 * time.Millisecond)
			return nil
		},
		5*time.Millisecond,
		20*time.Millisecond,
	)

	_, detectedTimeout := retryErr.(ErrTimeout)
	if detectedTimeout {
		t.FailNow()
	}
}

// WaitGroup with timeout, returns true when it's a timeout
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c: // OK
		return false
	case <-time.After(timeout): // timeout
		return true
	}
}

func TestNeverTimeouts(t *testing.T) {
	retryErr := WhileUnsuccessful(
		func() error {
			time.Sleep(300 * time.Millisecond)
			return nil
		},
		5*time.Millisecond,
		20*time.Millisecond,
	)

	_, detectedTimeout := retryErr.(ErrTimeout)
	if detectedTimeout {
		t.FailNow()
	}
}

func TestNeverTimeoutsAgain(t *testing.T) {
	retryErr := WhileUnsuccessful(
		func() error {
			time.Sleep(300 * time.Millisecond)
			return fmt.Errorf("forever fails")
		},
		5*time.Millisecond,
		20*time.Millisecond,
	)

	_, detectedTimeout := retryErr.(ErrTimeout)
	if !detectedTimeout {
		t.FailNow()
	}
}

func TestDeath(t *testing.T) {
	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()
		retryErr := WhileUnsuccessful(
			func() error {
				time.Sleep(400 * time.Millisecond)
				return fmt.Errorf("timeout")
			},
			5*time.Millisecond,
			20*time.Millisecond,
		)

		_, detectedTimeout := retryErr.(ErrTimeout)
		if !detectedTimeout {
			t.FailNow()
		}
	}()

	detectedTimeout := waitTimeout(&wg, time.Millisecond*200)
	if !detectedTimeout {
		t.FailNow()
	}
}

func TestSurviveDeath(t *testing.T) {
	retryErr := WhileUnsuccessfulTimeout(
		func() error {
			time.Sleep(30 * time.Hour)
			return fmt.Errorf("timeout")
		},
		5*time.Millisecond,
		20*time.Millisecond,
	)

	_, detectedTimeout := retryErr.(ErrTimeout)
	if !detectedTimeout {
		t.FailNow()
	}
}

func TestHitTimeoutBasic(t *testing.T) {
	rand.Seed(86)

	hitTimeout := false
	notfound := false

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	for i := 0; i < 500; i++ {
		fmt.Println("--> Begin")
		var eserver string

		retryErr := WhileUnsuccessful(
			func() error {
				server, code, ierr := randomErrGen()
				if ierr != nil {
					switch code {
					case 404:
						// If error is "resource not found", we want to return GopherCloud error as-is to be able
						// to behave differently in this special case. To do so, stop the retry
						notfound = true
						return nil
					case 500:
						// When the response is "Internal Server Error", retries
						log.Debugf("received 'Internal Server Error', retrying...")
						return ierr
					case 667:
						return ierr
					default:
						// Any other error stops the retry
						log.Debugf("unexpected error")
						return nil
					}
				}

				if server == "" {
					return fmt.Errorf("error getting host, nil response from gophercloud")
				}
				eserver = server

				if code >= 300 {
					lastState := code - 300

					if lastState != 4 && lastState != 2 {
						return nil
					}
				}

				return fmt.Errorf("server not ready yet")
			},
			5*time.Millisecond,
			20*time.Millisecond,
		)
		if retryErr != nil {
			if _, ok := retryErr.(ErrTimeout); ok {
				fmt.Println("It IS a timeout !!")
				hitTimeout = true
				goto endgame
			}
			fmt.Printf("It's NOT a timeout !!: %s\n", retryErr.Error())
			goto endgame
		}
		if eserver == "" || notfound {
			fmt.Println("Not found !!")
			goto endgame
		}

		fmt.Println("Doing something else...")

	endgame:
		fmt.Println("This is it")
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)

	if !hitTimeout {
		t.Error(outString)
		t.FailNow()
	}
}

func alwaysFailsErrGen() (string, int, error) {
	ladder := rand.Intn(9)
	switch ladder {
	case 1:
		return "", 404, fmt.Errorf("error %d", 404)
	case 2:
		return "", 500, fmt.Errorf("error %d", 500)
	default:
		return "", 667, fmt.Errorf("error %d", 667)
	}
}

func TestHitTimeout(t *testing.T) {
	rand.Seed(86)

	hitTimeout := false
	notfound := false

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	for i := 0; i < 500; i++ {
		fmt.Println("--> Begin")
		var eserver string

		notfound = false

		retryErr := WhileUnsuccessful(
			func() error {
				server, code, ierr := alwaysFailsErrGen()
				if ierr != nil {
					switch code {
					case 404:
						// If error is "resource not found", we want to return GopherCloud error as-is to be able
						// to behave differently in this special case. To do so, stop the retry
						notfound = true
						return nil
					case 500:
						// When the response is "Internal Server Error", retries
						log.Debugf("received 'Internal Server Error', retrying...")
						return ierr
					case 667:
						return ierr
					default:
						// Any other error stops the retry
						log.Debug("unknown error")
						return nil
					}
				}

				if server == "" {
					return fmt.Errorf("error getting host, nil response from gophercloud")
				}
				eserver = server

				if code >= 300 {
					lastState := code - 300

					if lastState != 4 && lastState != 2 {
						return nil
					}
				}

				return fmt.Errorf("server not ready yet")
			},
			5*time.Millisecond,
			20*time.Millisecond,
		)
		if retryErr != nil {
			if _, ok := retryErr.(ErrTimeout); ok {
				fmt.Println("It's a timeout !!")
				hitTimeout = true
				goto endgame
			}
			fmt.Printf("It's NOT a timeout !!: %s\n", retryErr.Error())
			goto endgame
		}
		if eserver == "" || notfound {
			fmt.Println("Not found !!")
			goto endgame
		}

		fmt.Println("Doing something else...")

	endgame:
		fmt.Println("This is it")
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)

	if !hitTimeout {
		t.Error(outString)
		t.FailNow()
	}
}

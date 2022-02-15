//go:build race && ignore
// +build race,ignore

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

package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	_ "runtime/race"
	"strings"
	"testing"
)

func races() {
	wait := make(chan struct{})
	n := 0
	go func() {
		n++ // read, increment, write
		close(wait)
	}()
	n++ // conflicting access
	<-wait
}

func TestRace(t *testing.T) {
	raceParam := checkRacingParameters()
	if !raceParam {
		t.Errorf("This test MUST run with GORACE env variables")
		t.FailNow()
	}

	// Remove previous race checks
	files, _ := ioutil.ReadDir("./")
	for _, f := range files {
		if strings.Contains(f.Name(), "races") {
			_ = os.Remove(f.Name())
		}
	}

	races()

	there := false
	files, _ = ioutil.ReadDir("./")
	for _, f := range files {
		if strings.Contains(f.Name(), "races") {
			fmt.Println(f.Name())
			there = true
			break
		}
	}

	if !there {
		t.Errorf("This test MUST use -race flag")
		t.FailNow()
	}

	t.SkipNow()
}

func checkRacingParameters() bool {
	there := false
	for _, env := range os.Environ() {
		if strings.Contains(env, "GORACE") {
			there = true
			break
		}
	}
	return there
}

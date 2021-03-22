// +build debug

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

package errcontrol

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// this is the function pointer to the function that will panic
var crash func(...int)

func CrasherWithDescription(in error, description string, calldepth ...int) (err error) {
	defer func() {
		rerr := recover()
		if _, ok := rerr.(error); ok {
			err = rerr.(error)
		} else {
			err = fmt.Errorf("error %s: %v", description, rerr)
		}
	}()
	if in != nil {
		return in
	}
	if crash != nil {
		crash(calldepth...)
	}
	return nil
}

func Crasher(in error, calldepth ...int) (err error) {
	defer func() {
		rerr := recover()
		if _, ok := rerr.(error); ok {
			err = rerr.(error)
		} else {
			err = fmt.Errorf("error: %v", rerr)
		}
	}()
	if in != nil {
		return in
	}
	if crash != nil {
		crash(calldepth...)
	}
	return nil
}

func CrasherFail(in fail.Error, calldepth ...int) (err fail.Error) {
	defer func() {
		rerr := recover()
		if _, ok := rerr.(error); ok {
			err = fail.ConvertError(rerr.(error))
		} else {
			err = fail.ConvertError(fmt.Errorf("error: %v", rerr))
		}
	}()
	if in != nil {
		return in
	}
	if crash != nil {
		crash(calldepth...)
	}

	return nil
}

// CrashSetup should be called to configure crash sites in your code. It parses
// and saves a list of crash sites and their probabilities of crashing, and then
// makes the crash() function crash probabilistically when called from one of
// the specified crash sites. An example spec:
//   client.go:53:.003,server.go:18:.02
// That will cause a crash .003 of the time at client.go line 53, and .02 of the time
// at server.go line 18.
func CrashSetup(spec string) error {
	if spec == "" { // Crashing is disabled
		crash = nil
		return nil
	}

	// site stores the parsed file/line pairs from the config
	type site struct {
		file string
		line int64
	}

	sites := make(map[site]float64)
	for _, s := range strings.Split(spec, ",") {
		file, line, probability, err := newSite(s)
		if err != nil {
			return err
		}
		sites[site{file: file, line: line}] = probability
	}

	// Generate the function that causes crashes.
	crash = func(calldepth ...int) {
		file, line, err := getCallSite(calldepth...)
		if err != nil {
			return
		}

		chance := sites[site{
			file: file,
			line: int64(line),
		}]

		if chance > 0 && rand.Float64() <= chance {
			panic(fmt.Sprintf("crash injected at %s:%d, probability %f", file, line, chance))
		}
	}

	return nil
}

func getCallSite(calldepth ...int) (string, int, error) {
	depth := 3
	if len(calldepth) > 0 {
		depth = calldepth[0]
	}
	_, file, line, ok := runtime.Caller(depth)
	if !ok {
		file = ""
		line = 0
		return file, line, fmt.Errorf("problem inspecting runtume.Caller")
	}
	file = filepath.Base(file)
	return file, line, nil
}

// Parse a crash site spec; return values: line, file, probability, error
func newSite(s string) (string, int64, float64, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 3 {
		file := parts[0]
		line, intParseErr := strconv.ParseInt(parts[1], 10, 64)
		if intParseErr == nil {
			prob, floatParseErr := strconv.ParseFloat(parts[2], 64)
			if floatParseErr == nil {
				return file, line, prob, nil
			}
		}
	}
	return "", 0, 0, fmt.Errorf("invalid crash site spec '%s'", s)
}

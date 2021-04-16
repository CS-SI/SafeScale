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

package debug

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// this is the function pointer to the function that will panic
var originalCrash func(...int)
var crash func(...int) error

func CrasherWithDescription(in error, description string, calldepth ...int) (err error) {
	defer func() {
		rerr := recover()
		if _, ok := rerr.(error); ok {
			err = rerr.(error)
		} else {
			if rerr != nil {
				err = fmt.Errorf("error %s: %v", description, rerr)
			}
		}
	}()
	if in != nil {
		return in
	}
	if originalCrash != nil {
		originalCrash(calldepth...)
	}
	return nil
}

// // InjectPlannedError generates an error if planned, 'in' being an error of not
// func InjectPlannedError(in error, calldepth ...int) (err error) {
// 	defer func() {
// 		rerr := recover()
// 		if _, ok := rerr.(error); ok {
// 			err = rerr.(error)
// 		} else {
// 			if rerr != nil {
// 				err = fmt.Errorf("error: %v", rerr)
// 			}
// 		}
// 	}()
// 	if in != nil {
// 		return in
// 	}
// 	if originalCrash != nil {
// 		originalCrash(calldepth...)
// 	}
// 	return nil
// }

// InjectPlannedError generates an error if planned, 'in' being an error of not
func InjectPlannedError(in error, calldepth ...int) error {
	if in != nil {
		return in
	}

	if crash != nil {
		return crash(calldepth...)
	}

	return nil
}

// // FailIfPlanned returns 'in' if it's not nil (an error occurred), or generates one if 'in' is nil
// func FailIfPlanned(in fail.Error, calldepth ...int) (err fail.Error) {
// 	defer func() {
// 		rerr := recover()
// 		if _, ok := rerr.(error); ok {
// 			err = fail.ConvertError(rerr.(error))
// 		} else {
// 			if rerr != nil {
// 				err = fail.ConvertError(fmt.Errorf("error: %v", rerr))
// 			}
// 		}
// 	}()
// 	if in != nil {
// 		return in
// 	}
// 	if originalCrash != nil {
// 		return originalCrash(calldepth...)
// 	}
//
// 	return nil
// }

// InjectPlannedFail returns 'in' if it's not nil (an error occurred), or generates one if 'in' is nil
func InjectPlannedFail(in fail.Error, calldepth ...int) (err fail.Error) {
	if in != nil {
		return in
	}

	if crash != nil {
		if err := crash(calldepth...); err != nil {
			return fail.AbortedError(err, "planned error injected")
		}
	}

	return nil
}

// setup is called by InitializeErrorInjector() to configure originalCrash sites in your code. It parses
// and saves a list of originalCrash sites and their probabilities of crashing, and then
// makes the originalCrash() function originalCrash probabilistically when called from one of
// the specified originalCrash sites. An example spec:
//   client.go:53:.003,server.go:18:.02
// That will cause a originalCrash .003 of the time at client.go line 53, and .02 of the time
// at server.go line 18.
func setup(spec string) error {
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
	// originalCrash = func(calldepth ...int) {
	// 	file, line, err := getCallSite(calldepth...)
	// 	if err != nil {
	// 		return
	// 	}
	//
	// 	chance := sites[site{
	// 		file: file,
	// 		line: int64(line),
	// 	}]
	//
	// 	if chance > 0 && rand.Float64() <= chance {
	// 		panic(fmt.Sprintf("originalCrash injected at %s:%d, probability %f", file, line, chance))
	// 	}
	// }

	crash = func(calldepth ...int) error {
		file, line, err := getCallSite(calldepth...)
		if err != nil {
			return fmt.Errorf("failed to inject error at %s:%d: %v", file, line, err)
		}

		chance := sites[site{
			file: file,
			line: int64(line),
		}]

		if chance > 0 && rand.Float64() <= chance {
			err := fmt.Errorf("error injected at %s:%d, probability %f", file, line, chance)
			logrus.Debug(err.Error())
			return err
		}

		return nil
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
		return file, line, fmt.Errorf("problem inspecting runtime.Caller")
	}
	file = filepath.Base(file)
	return file, line, nil
}

// Parse a originalCrash site spec; return values: line, file, probability, error
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
	return "", 0, 0, fmt.Errorf("invalid originalCrash site spec '%s'", s)
}

// InitializeErrorInjector loads error plans from environment and setup the error injector
func init() {
	if errorPlans := os.Getenv("SAFESCALE_PLANNED_ERRORS"); errorPlans != "" {
		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			logrus.Warnf("Reloading planned errors: %s", errorPlans)
		}
		_ = setup(errorPlans)
	}
}

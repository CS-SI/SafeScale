//go:build debug
// +build debug

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

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// this is the function pointer to the function that will panic
// var originalCrash func(...int)
var crash func(...int) error

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

// InjectPlannedFailWithDescription returns 'in' if it's not nil (an error occurred), or generates one if 'in' is nil
func InjectPlannedFailWithDescription(in fail.Error, description string, calldepth ...int) (err fail.Error) {
	if in != nil {
		return in
	}

	if crash != nil {
		if err := crash(calldepth...); err != nil {
			return fail.AbortedError(err, "%s: planned error injected", description)
		}
	}

	return nil
}

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

type crashTrigger interface {
	DoCrash() bool
	Why() string
}

type probabilityTrigger struct {
	p float64
}

func (t probabilityTrigger) DoCrash() bool {
	return t.p > 0 && rand.Float64() <= t.p
}

func (t probabilityTrigger) Why() string {
	return fmt.Sprintf("probability %f", t.p)
}

type onceTrigger struct {
	count  int64
	target int64
}

func (o *onceTrigger) DoCrash() bool {
	o.count++
	return o.target == o.count
}

func (o onceTrigger) Why() string {
	return fmt.Sprintf("iteration %d", o.target)
}

type iterationTrigger struct {
	count int64
	max   int64
}

func (t *iterationTrigger) DoCrash() bool {
	t.count++
	return t.max > 0 && t.count >= t.max
}

func (t iterationTrigger) Why() string {
	return fmt.Sprintf("iteration %d", t.max)
}

// setup is called by InitializeErrorInjector() to configure crash sites in your code. It parses
// and saves a list of originalCrash sites and their probabilities of crashing, and then
// makes the crash() function crash with appropriate trigger when called from one of
// the specified crash sites. An example spec:
//
//	client.go:53:p:.003,server.go:18:p:.02,validate.go:25:i:3
//
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

	// sites := make(map[site]float64)
	sites := make(map[site]crashTrigger)
	for _, s := range strings.Split(spec, ",") {
		// file, line, probability, err := newSite(s)
		file, line, trigger, err := newSite(s)
		if err != nil {
			return err
		}

		sites[site{file: file, line: line}] = trigger
	}

	crash = func(calldepth ...int) error {
		file, line, err := getCallSite(calldepth...)
		if err != nil {
			return fmt.Errorf("failed to inject error at %s:%d: %v", file, line, err)
		}

		trigger := sites[site{
			file: file,
			line: int64(line),
		}]

		if trigger != nil && trigger.DoCrash() {
			err := fmt.Errorf("error injected at %s:%d, %s", file, line, trigger.Why())
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

// Parse a crash site spec; return values: line, file, crashTrigger, error
// func newSite(s string) (string, int64, float64, error) {
func newSite(s string) (string, int64, crashTrigger, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 4 {
		file := parts[0]
		line, intParseErr := strconv.ParseInt(parts[1], 10, 64)
		if intParseErr != nil {
			return "", 0, nil, fmt.Errorf("invalid crash site spec '%s'", s)
		}

		switch parts[2] {
		case "p":
			prob, err := strconv.ParseFloat(parts[3], 64)
			if err != nil {
				return "", 0, nil, fmt.Errorf("invalid crash site spec '%s'", s)
			}
			return file, line, &probabilityTrigger{prob}, nil
		case "i":
			iter, err := strconv.ParseInt(parts[3], 10, 64)
			if err != nil {
				return "", 0, nil, fmt.Errorf("invalid crash site spec '%s'", s)
			}
			return file, line, &iterationTrigger{max: iter}, nil
		case "o": // once
			iter, err := strconv.ParseInt(parts[3], 10, 64)
			if err != nil {
				return "", 0, nil, fmt.Errorf("invalid crash site spec '%s'", s)
			}
			return file, line, &onceTrigger{target: iter}, nil
		}
	}
	return "", 0, nil, fmt.Errorf("invalid crash site spec '%s'", s)
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

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

package main

import (
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/makholm/covertool/pkg/cover"
	"github.com/makholm/covertool/pkg/exit"
)

func TestMain(m *testing.M) {
	cover.ParseAndStripTestFlags()

	// Make sure we have the opportunity to flush the coverage report to disk when
	// terminating the process.
	exit.AtExit(cover.FlushProfiles)

	// If the test binary name is "calc" we've are being asked to run the
	// coverage-instrumented calc.

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}

	if path.Base(os.Args[0]) == "safescaled-cover"+suffix {
		main()
		exit.Exit(0)
	}

	os.Exit(m.Run())
}

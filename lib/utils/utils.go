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

package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// AbsPathify ...
func AbsPathify(inPath string) string {
	r := regexp.MustCompile(`(\$[\{]{1}[A-Z]+[\}]{1})|(\$[A-Z]+)`)
	found := r.FindAllString(inPath, -1)

	// Special variable treatment goes here
	overrides := map[string]string{}
	overrides["HOME"] = userHomeDir()

	// found contains strings such as $HOME or ${HOME}, we transform that into HOME, then search HOME in overrides first, then in os.Getenv
	for _, key := range found {
		ks := ""
		if strings.Contains(key, "{") {
			ks = key[2 : len(key)-1]
		} else {
			ks = key[1:]
		}

		if val, ok := overrides[ks]; ok {
			inPath = strings.ReplaceAll(inPath, key, val)
		} else {
			inPath = strings.ReplaceAll(inPath, key, os.Getenv(ks))
		}
	}

	if filepath.IsAbs(inPath) {
		return filepath.Clean(inPath)
	}

	p, err := filepath.Abs(inPath)
	if err != nil {
		return ""
	}

	return filepath.Clean(p)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

// UserConfirmed asks user to confirm
func UserConfirmed(msg string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ? (y/N): ", msg)
	resp, _ := reader.ReadString('\n')
	resp = strings.ToLower(strings.TrimSuffix(resp, "\n"))
	return resp == "y"
}

// ExtractRetCode extracts info from the error
func ExtractRetCode(err error) (_ string, _ int, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	retCode := -1
	msg := "__ NO MESSAGE __"
	if ee, ok := err.(*exec.ExitError); ok {
		// Try to get retCode
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			retCode = status.ExitStatus()
		} else {
			return msg, retCode, fail.NewError("ExitError.Sys is not a 'syscall.WaitStatus'")
		}
		// Retrieve error Message
		msg = ee.Error()
		return msg, retCode, nil
	}
	return msg, retCode, fail.NewError("error is not an 'ExitError'")
}

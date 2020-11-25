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

package callstack

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
)

var sourceFileRemovePart atomic.Value

// SourceFilePathUpdater returns a function to alter source file path, if debug is not enabled
func SourceFilePathUpdater() func(string) string {
	var (
		fn func(string) string
	)
	// if app.Debug {
	// VPL: disabled for further thinking...
	// Do not change anything in source file path
	fn = func(path string) string { return path }
	// } else {
	//     // Alter filepath to remove absolute part (that may not exist)
	//     removePath := sourceFilePrefixToRemove()
	//     fn = func(path string) string {
	//         return strings.Replace(path, removePath, "", 1)
	//     }
	// }
	return fn
}

const (
	defaultPartToRemove    = "go/src/github.com/CS-SI/SafeScale/"
	sourceFileSearchString = "github.com/CS-SI/SafeScale/"
)

// sourceFilePrefixToRemove returns the part of the file path to remove before display.
func sourceFilePrefixToRemove() string {
	if anon := sourceFileRemovePart.Load(); anon != nil {
		return anon.(string)
	}
	return defaultPartToRemove
}

func init() {
	var rootPath string
	if _, f, _, ok := runtime.Caller(0); ok {
		rootPath = strings.TrimRight(strings.Split(f, sourceFileSearchString)[0], "/")
		rootPath = filepath.Dir(filepath.Dir(rootPath))
	}
	sourceFileRemovePart.Store(rootPath)
}

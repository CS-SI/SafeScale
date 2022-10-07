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
	"io"
	"io/ioutil"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// LazyRemove is identical to os.Remove, but doesn't raise an error, and
// log.Warn every error except "file not found" which is ignored
func LazyRemove(path string) fail.Error {
	if err := os.Remove(path); err != nil {
		switch err.(type) {
		case *os.PathError:
			// File not found, that's ok because we wanted to remove it...
		default:
			return fail.Wrap(err, "failed to remove file '%s'", path)
		}
	}
	return nil
}

// CreateTempFileFromString creates a temporary file containing 'content'
func CreateTempFileFromString(content string, filemode os.FileMode) (*os.File, fail.Error) {
	defaultTmpDir := os.TempDir()

	f, err := ioutil.TempFile(defaultTmpDir, "")
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to create temporary file")
	}
	_, err = f.WriteString(content)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to wrote string to temporary file")
	}

	err = f.Chmod(filemode)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to change temporary file access rights")
	}

	err = f.Close()
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to close temporary file")
	}

	return f, nil
}

// Mkdir creates a folder with appropriate ownership
func Mkdir(path string, rights os.FileMode, uid, gid int) fail.Error {
	state, err := os.Stat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			err = os.MkdirAll(path, rights)
			if err != nil {
				return fail.Wrap(err, "failed to create folder '%s'", path)
			}

			err := os.Chown(path, uid, gid)
			if err != nil {
				return fail.Wrap(err)
			}

			state, err = os.Stat(path)
			if err != nil {
				return fail.Wrap(err)
			}

		default:
			return fail.Wrap(err)
		}
	}
	if !state.IsDir() {
		return fail.NotAvailableError("'%s' exists but is not a folder", path)
	}

	return nil
}

// CopyFile copies a file
func CopyFile(source, destination string) (int64, fail.Error) {
	// copy file in temporary run folder
	src, err := os.Open(source)
	if err != nil {
		return 0, fail.Wrap(err, "failed to open file '%s'", source)
	}
	defer func() { _ = src.Close() }()

	dest, err := os.Create(destination)
	if err != nil {
		return 0, fail.Wrap(err, "failed to create file '%s'", destination)
	}
	defer func() { _ = dest.Close() }()

	n, err := io.Copy(dest, src)
	if err != nil {
		return 0, fail.Wrap(err, "failed to copy '%s' to '%s'", source, destination)
	}

	return n, nil
}

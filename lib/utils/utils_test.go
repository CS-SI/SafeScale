/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TODO Remove this later
func OriginalAbsPathify(inPath string) string {
	if strings.HasPrefix(inPath, "$HOME") {
		inPath = userHomeDir() + inPath[5:]
	}

	if strings.HasPrefix(inPath, "$") {
		end := strings.Index(inPath, string(os.PathSeparator))
		inPath = os.Getenv(inPath[1:end]) + inPath[end:]
	}

	if filepath.IsAbs(inPath) {
		return filepath.Clean(inPath)
	}

	p, err := filepath.Abs(inPath)
	if err == nil {
		return filepath.Clean(p)
	}

	return ""
}

func TestAbsPathify(t *testing.T) {
	pwd, _ := os.Getwd()
	user := os.Getenv("USER")

	type args struct {
		inPath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"first", args{inPath: "."}, pwd},
		{"second", args{inPath: "$HOME/.safescale"}, "/home/" + user + "/.safescale"},
		{"third", args{inPath: "$HOME/.config/safescale"}, "/home/" + user + "/.config/safescale"},
		{"last", args{inPath: "/etc/safescale"}, "/etc/safescale"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					fmt.Println("The code did not panic, :)")
				} else {
					t.Errorf("Horrible failure")
				}
			}()
			if got := AbsPathify(tt.args.inPath); got != tt.want {
				t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOriginalAbsPathify(t *testing.T) {
	pwd, _ := os.Getwd()
	user := os.Getenv("USER")

	type args struct {
		inPath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"first", args{inPath: "."}, pwd},
		{"second", args{inPath: "$HOME/.safescale"}, "/home/" + user + "/.safescale"},
		{"third", args{inPath: "$HOME/.config/safescale"}, "/home/" + user + "/.config/safescale"},
		{"last", args{inPath: "/etc/safescale"}, "/etc/safescale"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					fmt.Println("The code did not panic, :)")
				} else {
					t.Errorf("Horrible failure")
				}
			}()
			if got := OriginalAbsPathify(tt.args.inPath); got != tt.want {
				t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
			}
		})
	}
}

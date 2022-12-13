//go:build alltests
// +build alltests

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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_AbsPathify(t *testing.T) {

	pwd, _ := os.Getwd()
	user := os.Getenv("USER")
	tests := []struct {
		name     string
		inPath   string
		want     string
		exact    bool
		included bool
	}{
		{name: "test1", inPath: ".", want: pwd, exact: true, included: true},
		{name: "test2", inPath: "$HOME/.safescale", want: "/home/" + user + "/.safescale", exact: true, included: true},
		{name: "test3", inPath: "$HOME/.config/safescale", want: "/home/" + user + "/.config/safescale", exact: true, included: true},
		{name: "test4", inPath: "/etc/safescale", want: "/etc/safescale", exact: true, included: true},
		{name: "test5", inPath: "{}", want: "{}", exact: false, included: true},
		{name: "test6", inPath: "${HOME}", want: "${HOME}", exact: false, included: false},
		{name: "test7", inPath: "${HOME}///////////notfound", want: "${HOME}", exact: false, included: false},
		{name: "test8", inPath: "${HOME}///////////notfound", want: "//", exact: false, included: false},
		{name: "test8", inPath: "${MANY}/some", want: "/some", exact: true, included: true},
	}
	for _, tt := range tests {
		if !(runtime.GOOS != "linux") {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Horrible failure")
					}
				}()
				got := AbsPathify(tt.inPath)
				if tt.included && tt.exact && got != tt.want {
					t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
				}
				if tt.included && !tt.exact && !strings.Contains(got, tt.want) {
					t.Errorf("AbsPathify() = %v, want contains %v", got, tt.want)
				}
				if !tt.included && tt.exact && got == tt.want {
					t.Errorf("AbsPathify() = %v, want not %v", got, tt.want)
				}
				if !tt.included && !tt.exact && strings.Contains(got, tt.want) {
					t.Errorf("AbsPathify() = %v, want not contains %v", got, tt.want)
				}
			}()

			result := AbsPathify("{}")
			require.Contains(t, result, "{}")

		}
	}

}

//func OriginalAbsPathify(inPath string) string {
//	if strings.HasPrefix(inPath, "$HOME") {
//		inPath = userHomeDir() + inPath[5:]
//	}
//
//	if strings.HasPrefix(inPath, "$") {
//		end := strings.Index(inPath, string(os.PathSeparator))
//		inPath = os.Getenv(inPath[1:end]) + inPath[end:]
//	}
//
//	if filepath.IsAbs(inPath) {
//		return filepath.Clean(inPath)
//	}
//
//	p, err := filepath.Abs(inPath)
//	if err == nil {
//		return filepath.Clean(p)
//	}
//
//	return ""
//}

//func TestOriginalAbsPathify(t *testing.T) {
//	pwd, _ := os.Getwd()
//	user := os.Getenv("USER")
//
//	type args struct {
//		inPath string
//	}
//	tests := []struct {
//		name string
//		args args
//		want string
//	}{
//		{"first", args{inPath: "."}, pwd},
//		{"second", args{inPath: "$HOME/.safescale"}, "/home/" + user + "/.safescale"},
//		{"third", args{inPath: "$HOME/.config/safescale"}, "/home/" + user + "/.config/safescale"},
//		{"last", args{inPath: "/etc/safescale"}, "/etc/safescale"},
//	}
//	for _, tt := range tests {
//		if !(runtime.GOOS != "linux" && (strings.Contains(tt.want, "home") || strings.Contains(tt.want, "etc"))) {
//			t.Run(tt.name, func(t *testing.T) {
//				defer func() {
//					if r := recover(); r == nil {
//						fmt.Println("The code did not panic, :)")
//					} else {
//						t.Errorf("Horrible failure")
//					}
//				}()
//				if got := OriginalAbsPathify(tt.args.inPath); got != tt.want {
//					t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
//				}
//			})
//		}
//	}
//}

func Test_userHomeDir(t *testing.T) {

	original := os.Getenv("HOME")

	tests := []struct {
		path string
	}{
		{path: "/home/root"},
		{path: "/home/safescale"},
		{path: "/usr/local/bin"},
		{path: "C:\\user\\root"},
		{path: "i'm broken, but it works ?"},
	}
	for _, tt := range tests {
		os.Setenv("HOME", tt.path)
		given := userHomeDir()
		require.EqualValues(t, given, tt.path)
	}

	os.Setenv("HOME", original)
}

func Test_ExtractRetCode(t *testing.T) {

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("timeout", "1")
	} else {
		cmd = exec.Command("bash", "-c", "sleep 1")
	}
	if err := cmd.Start(); err != nil {
		t.Error(err)
		t.Fail()
	} else {
		err := cmd.Process.Kill()
		if err != nil {
			t.FailNow()
		}
		err = cmd.Wait()
		fmt.Println(err)
		defer func() {
			r := recover()
			fmt.Println(r)
		}()
		result, ret, xerr := ExtractRetCode(err)
		fmt.Println(result, ret, xerr.Error())
	}

}

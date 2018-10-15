/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

import "testing"

func TestAbsPathify(t *testing.T) {
	type args struct {
		inPath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"first", args{inPath:"."}, "/home/oscar/GoLand/src/github.com/CS-SI/SafeScale/utils"},
		{"second", args{inPath:"$HOME/.safescale"}, "/home/oscar/.safescale"},
		{"third", args{inPath:"$HOME/.config/safescale"}, "/home/oscar/.config/safescale"},
		{"last", args{inPath:"/etc/safescale"}, "/etc/safescale"},
		{"gopath", args{inPath:"$GOPATH"}, "/home/oscar/GoLand"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AbsPathify(tt.args.inPath); got != tt.want {
				t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOriginalAbsPathify(t *testing.T) {
	type args struct {
		inPath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"first", args{inPath:"."}, "/home/oscar/GoLand/src/github.com/CS-SI/SafeScale/utils"},
		{"second", args{inPath:"$HOME/.safescale"}, "/home/oscar/.safescale"},
		{"third", args{inPath:"$HOME/.config/safescale"}, "/home/oscar/.config/safescale"},
		{"last", args{inPath:"/etc/safescale"}, "/etc/safescale"},
		{"gopath", args{inPath:"$GOPATH"}, "$GOPATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OriginalAbsPathify(tt.args.inPath); got != tt.want {
				t.Errorf("AbsPathify() = %v, want %v", got, tt.want)
			}
		})
	}
}


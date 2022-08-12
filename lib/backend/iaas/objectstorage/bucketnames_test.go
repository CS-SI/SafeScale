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

package objectstorage

import (
	"os"
	"testing"
)

func TestBuildMetadataBucketName(t *testing.T) {
	type args struct {
		driver  string
		region  string
		domain  string
		project string
	}

	suffix := ""
	if newsuffix, ok := os.LookupEnv(suffixEnvName); ok {
		suffix = "." + newsuffix
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"first", args{
			driver:  "a",
			region:  "b",
			domain:  "c",
			project: "d",
		}, "0.safescale-449a7986e14ff78da8c3053229f4f1d2" + suffix, false},
		{"second", args{
			driver:  "a",
			region:  "c",
			domain:  "b",
			project: "d",
		}, "0.safescale-39aa5fec414ff78da8c3028953851096" + suffix, false},
		{"second insensitive", args{
			driver:  "a",
			region:  "c",
			domain:  "b",
			project: "D",
		}, "0.safescale-39aa5fec414ff78da8c3028953851096" + suffix, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildMetadataBucketName(tt.args.driver, tt.args.region, tt.args.domain, tt.args.project)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildMetadataBucketName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildMetadataBucketName() got = %v, want %v", got, tt.want)
			}
		})
	}
}

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

package converters

// Contains functions that are used to convert from everything else

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func Test_BucketListToProtocol(t *testing.T) {

	buckets := []string{
		"Bucket1",
		"Bucket2",
		"Bucket3",
		"Bucket4",
		"Bucket5",
	}
	bl := BucketListToProtocol(buckets)
	if reflect.TypeOf(bl).String() != "*protocol.BucketListResponse" {
		t.Error("Expect type *protocol.BucketListResponse")
		t.FailNow()
	}
	var match = true
	for i := range buckets {
		if buckets[i] != bl.Buckets[i].Name {
			match = false
		}
	}
	if !match {
		t.Error("Converter mismatch")
		t.Fail()
	}

}

func Test_NFSExportOptionsFromStringToProtocol(t *testing.T) {

	tests := map[string]int{
		"":                               0,
		"read_only":                      1,
		"root_squash":                    2,
		"read_only,root_squash":          3,
		"root_squash,no_root_squash":     0,
		"secure":                         4,
		"secure,insecure":                0,
		"async":                          8,
		"async,sync":                     0,
		"nohide":                         16,
		"crossmnt":                       32,
		"subtree_check":                  64,
		"subtree_check,no_subtree_check": 0,
	}
	nfsOpt := &protocol.NFSExportOptions{}
	packed := 0
	for name, value := range tests {
		nfsOpt = NFSExportOptionsFromStringToProtocol(name)
		packed = 0
		if nfsOpt.ReadOnly {
			packed += 1
		}
		if nfsOpt.RootSquash {
			packed += 2
		}
		if nfsOpt.Secure {
			packed += 4
		}
		if nfsOpt.Async {
			packed += 8
		}
		if nfsOpt.NoHide {
			packed += 16
		}
		if nfsOpt.CrossMount {
			packed += 32
		}
		if nfsOpt.SubtreeCheck {
			packed += 64
		}
		if packed != value {
			t.Error("Converter mismatch")
			t.Fail()
		}
	}

}

func Test_HostSizingRequirementsFromStringToAbstract(t *testing.T) {

	invalids := map[string]string{
		",]-[,":            "*fail.ErrSyntax",
		"cpu >= a":         "*fail.ErrInvalidRequest",
		"cpu >= 0.666":     "*fail.ErrSyntax",
		"cpu <= a":         "*fail.ErrInvalidRequest",
		"cpu <= 0.666":     "*fail.ErrSyntax",
		"count = a":        "*fail.ErrInvalidRequest",
		"count = 0.666":    "*fail.ErrInvalidRequest",
		"count = false":    "*fail.ErrInvalidRequest",
		"count ~ 3":        "only use =",
		"cpufreq >= a":     "*fail.ErrInvalidRequest",
		"cpufreq >= false": "*fail.ErrSyntax",
		"cpufreq <= a":     "*fail.ErrInvalidRequest",
		"cpufreq <= false": "*fail.ErrSyntax",
		"gpu >= a":         "*fail.ErrInvalidRequest",
		"gpu >= 0.666":     "*fail.ErrSyntax",
		"gpu >= false":     "*fail.ErrSyntax",
		"ram >= a":         "*fail.ErrInvalidRequest",
		"ram >= false":     "*fail.ErrSyntax",
		"ram <= a":         "*fail.ErrInvalidRequest",
		"ram <= false":     "*fail.ErrSyntax",
		"disk >= a":        "*fail.ErrInvalidRequest",
		"disk >= 0.666":    "*fail.ErrSyntax",
		"template <=> ;)":  "*fail.ErrSyntax",
	}
	var err fail.Error

	for sizing, errName := range invalids {
		_, _, err = HostSizingRequirementsFromStringToAbstract(sizing)
		if err == nil {
			t.Error(fmt.Sprintf("In %s, Expect %s error", sizing, errName))
		}
	}

	hsr, _, err := HostSizingRequirementsFromStringToAbstract("cpu <= 4, ram <= 10, disk = 100")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	// require.EqualValues(t, hsr.MinCores, 0)
	require.EqualValues(t, hsr.MaxCores, 4)
	// require.EqualValues(t, hsr.MinRAMSize, 0)
	require.EqualValues(t, hsr.MaxRAMSize, 10)
	require.EqualValues(t, hsr.MinDiskSize, 100)
	// require.EqualValues(t, hsr.MinGPU, -1) // @TODO: Why here default is -1 and not 0 ?
	// require.EqualValues(t, hsr.MinCPUFreq, 0)

	hsr, _, err = HostSizingRequirementsFromStringToAbstract("cpu >= 1, ram >= 2, disk >= 150")
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	require.EqualValues(t, hsr.MinCores, 1)
	// require.EqualValues(t, hsr.MaxCores, 0)
	require.EqualValues(t, hsr.MinRAMSize, 2)
	// require.EqualValues(t, hsr.MaxRAMSize, 0)
	require.EqualValues(t, hsr.MinDiskSize, 150)
	// require.EqualValues(t, hsr.MinGPU, -1) // @TODO: Why here default is -1 and not 0 ?
	// require.EqualValues(t, hsr.MinCPUFreq, 0)

}

func Test_NodeCountFromStringToInteger(t *testing.T) {

	invalids := map[string]string{
		",]-[,": "*fail.ErrSyntax",
	}
	var err fail.Error
	var i int
	for sizing, errName := range invalids {
		_, err = NodeCountFromStringToInteger(sizing)
		if err == nil {
			t.Error(fmt.Sprintf("%s failed: Expected %s error", sizing, errName))
		}
	}
	invalids = map[string]string{
		"count ~ 3":        "only use =",
		"cpu >= a":         "*fail.ErrInvalidRequest",
		"cpu >= 0.666":     "*fail.ErrSyntax",
		"cpu <= a":         "*fail.ErrInvalidRequest",
		"cpu <= 0.666":     "*fail.ErrSyntax",
		"count = a":        "*fail.ErrInvalidRequest",
		"count = 0.666":    "*fail.ErrInvalidRequest",
		"count = false":    "*fail.ErrInvalidRequest",
		"cpufreq >= a":     "*fail.ErrInvalidRequest",
		"cpufreq >= false": "*fail.ErrSyntax",
		"cpufreq <= a":     "*fail.ErrInvalidRequest",
		"cpufreq <= false": "*fail.ErrSyntax",
		"gpu >= a":         "*fail.ErrInvalidRequest",
		"gpu >= 0.666":     "*fail.ErrSyntax",
		"gpu >= false":     "*fail.ErrSyntax",
		"ram >= a":         "*fail.ErrInvalidRequest",
		"ram >= false":     "*fail.ErrSyntax",
		"ram <= a":         "*fail.ErrInvalidRequest",
		"ram <= false":     "*fail.ErrSyntax",
		"disk >= a":        "*fail.ErrInvalidRequest",
		"disk >= 0.666":    "*fail.ErrSyntax",
		"template <=> ;)":  "*fail.ErrSyntax",
	}
	for sizing, _ := range invalids {
		i, err = NodeCountFromStringToInteger(sizing)
		if err != nil {
			t.Error(err)
			t.Fail()
		} else {
			if i != 0 {
				t.Error("Sizing has no count")
				t.Fail()
			}
		}
	}

}

func TestSizingToken_Push(t *testing.T) {

	var st *sizingToken = nil
	err := st.Push("one")
	if err == nil {
		t.Error("Can't push in nil pointer")
		t.Fail()
	}
	st = newSizingToken()
	err = st.Push("one")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = st.Push("two")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = st.Push("three")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = st.Push("four")
	if err == nil {
		t.Error("Can't push, Sizing token is fuul (3 item max)")
		t.Fail()
	}

}

func TestSizingToken_GetKeyword(t *testing.T) {

	var err fail.Error
	var result string
	st := newSizingToken()
	result, err = st.GetKeyword()
	if err == nil {
		t.Error("Can't get keyword from empty sizingtoken")
		t.Fail()
	}
	err = st.Push("one")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	result, err = st.GetKeyword()
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if result != "one" {
		t.Error("GetKeyword restitute wrong value")
		t.Fail()
	}

}

func TestSizingToken_GetValue(t *testing.T) {

	var err fail.Error
	var result string
	st := newSizingToken()
	result, err = st.GetValue()
	if err == nil {
		t.Error("Can't get value from empty sizingtoken")
		t.Fail()
	}
	err = st.Push("one")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	result, err = st.GetValue()
	if err == nil {
		t.Error("Can't get value from not full sizingtoken")
		t.Fail()
	}
	err = st.Push("two")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	result, err = st.GetValue()
	if err == nil {
		t.Error("Can't get value from not full sizingtoken")
		t.Fail()
	}
	err = st.Push("three")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	result, err = st.GetValue()
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if result != "three" {
		t.Error("GetValue restitute wrong value")
		t.Fail()
	}

}

func TestSizingToken_String(t *testing.T) {

	var st *sizingToken = nil
	var err fail.Error
	if st.String() != "" {
		t.Error("NIl sizingtoken can't be stringify")
		t.Fail()
	}
	st = newSizingToken()
	err = st.Push("one")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = st.Push("two")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if st.String() != "one two " {
		t.Error("String restitute wrong value")
		t.Fail()
	}

}

type sizingTokenTest struct {
	sizingToken   *sizingToken
	errorExpected string
	expectMin     string
	expectMax     string
}

func TestSizingToken_Validate(t *testing.T) {

	tests := []sizingTokenTest{
		{
			sizingToken:   nil,
			errorExpected: "token is not complete",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "~", "1"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"template", "~", "any"},
				pos:     3,
			},
			errorExpected: "'template' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "~", "1go"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "~", "1go"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "~", "1024"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1024",
			expectMax:     "2048",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "~", "1024.50"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1024.5",
			expectMax:     "2049.0",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"template", "=", "tplname"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "tplname",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "=", "[1024-2048]"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1024",
			expectMax:     "2048",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "=", "[1024-2048-4096]"},
				pos:     3,
			},
			errorExpected: "'ram' token isn't a valid interval",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "=", "[e-14]"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "=", "[1-f]"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "=", "e"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "=", "1"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1",
			expectMax:     "1",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "<", "3"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"template", "<", "tplName"},
				pos:     3,
			},
			errorExpected: "'template' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "<", "any"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "lt", "1024"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "",
			expectMax:     "1023",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "<", "1024"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "",
			expectMax:     "1023",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "<", "1024.0"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "",
			expectMax:     "1023.9",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "<=", "3"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "le", "4096"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "",
			expectMax:     "4096",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", ">", "0"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"template", ">", "tplName"},
				pos:     3,
			},
			errorExpected: "'template' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", ">", "1go"},
				pos:     3,
			},
			errorExpected: "'ram' isn't a valid number",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", ">", "0"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", "gt", "0"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "1",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"ram", ">", "0.5"},
				pos:     3,
			},
			errorExpected: "",
			expectMin:     "0.6",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", ">=", "1"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "ge", "1"},
				pos:     3,
			},
			errorExpected: "'count' can only use '='",
			expectMin:     "",
			expectMax:     "",
		},
		{
			sizingToken: &sizingToken{
				members: []string{"count", "!=", "1"},
				pos:     3,
			},
			errorExpected: "operator '!=' of token 'count' is not supported",
			expectMin:     "",
			expectMax:     "",
		},
	}

	for i := range tests {
		test := tests[i]
		min, max, err := test.sizingToken.Validate()
		if test.errorExpected == "" && err != nil {
			t.Error(err)
		}
		if test.errorExpected != "" && err == nil {
			t.Error(fmt.Sprintf("Expect error \"%s\"", test.errorExpected))
		}
		if test.errorExpected == "" {
			if min != test.expectMin || max != test.expectMax {
				t.Error(fmt.Sprintf("Invalid returned value [%s, %s], expect [%s, %s]", min, max, test.expectMin, test.expectMax))
			}
		}
		if test.errorExpected != "" {
			if min != test.expectMin || max != test.expectMax || !strings.Contains(err.Error(), test.errorExpected) {
				t.Error(fmt.Sprintf("Invalid returned value [%s, %s, %s], expect [%s, %s, %s]", min, max, err.Error(), test.expectMin, test.expectMax, test.errorExpected))
			}
		}
	}

}

type parseSizingTest struct {
	request       string
	errorExpected string
	ramExpected   string
}

func TestRequest_parseSizingString(t *testing.T) {

	tests := []parseSizingTest{
		{
			request:       "ram = [1024-2048]",
			errorExpected: "",
			ramExpected:   "ram = [1024-2048]",
		},
		{
			request:       "ram = [1024-2048",
			errorExpected: "",
			ramExpected:   "ram = [1024-2048",
		},
		{
			request:       "ram = [1024-2048], gpu = -1, disk ~ 4096",
			errorExpected: "",
			ramExpected:   "ram = [1024-2048]",
		},
		{
			request:       "ram = -1",
			errorExpected: "",
			ramExpected:   "ram = -1",
		},
		{
			request:       "ram = -1,ram = 2",
			errorExpected: "",
			ramExpected:   "ram = 2",
		},
		{
			request:       "ram 5",
			errorExpected: "",
			ramExpected:   "",
		},
		{
			request:       "ram = 5.3",
			errorExpected: "",
			ramExpected:   "ram = 5.3",
		},
		{
			request:       "ram === 5",
			errorExpected: "",
			ramExpected:   "ram = =",
		},
	}

	for i := range tests {
		test := tests[i]
		result, err := parseSizingString(test.request)

		fmt.Println(test.request, "____", result["ram"], err)

		if test.errorExpected == "" && err != nil {
			t.Error(err)
		}
		if test.errorExpected != "" && err == nil {
			t.Error(fmt.Sprintf("Expect error \"%s\"", test.errorExpected))
		}
		if test.errorExpected == "" && result["ram"].String() != test.ramExpected {
			t.Error(fmt.Sprintf("Return \"%s\" but expect \"%s\"", result["ram"], test.ramExpected))
		}
		if test.errorExpected != "" && result["ram"].String() != test.ramExpected {
			t.Error(fmt.Sprintf("Return \"%s\" but expect \"%s\"", result["ram"], test.ramExpected))
		}
	}
}

func Test_parseSizingString(t *testing.T) {
	hear_me_roar := "template=e2-medium,gpu = -1, disk >= 22"
	thing, err := parseSizingString(hear_me_roar)
	if err != nil {
		t.Error(err)
	}
	for k, v := range thing {
		_, _, err = v.Validate()
		if err != nil {
			t.Errorf("what is the problem with %s ?: %v", k, err)
			t.FailNow()
		}
	}
	t.Log(spew.Sdump(thing))
}

func Test_parseSizingString_disk(t *testing.T) {
	hear_me_roar := "template=e2-medium"
	thing, err := parseSizingString(hear_me_roar)
	if err != nil {
		t.Error(err)
	}
	for k, v := range thing {
		_, _, err = v.Validate()
		if err != nil {
			t.Errorf("what is the problem with %s ?: %v", k, err)
			t.FailNow()
		}
	}
	t.Log(spew.Sdump(thing))
}

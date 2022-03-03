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

package abstract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

type Test struct {
	caller    func(string, string) fail.Error
	checkName bool
	errorType string
}

func TestErrors_Global(t *testing.T) {
	tests := []Test{
		{caller: ResourceNotFoundError, errorType: "*fail.ErrNotFound"},
		{caller: ResourceNotAvailableError, errorType: "*fail.ErrNotAvailable"},
		{caller: ResourceDuplicateError, errorType: "*fail.ErrDuplicate"},
		{caller: ResourceInvalidRequestError, errorType: "*fail.ErrInvalidRequest"},
		{caller: ResourceForbiddenError, errorType: "*fail.ErrForbidden"},
	}
	test := Test{}
	ressourceNames := []string{"", "Ressource1", "A B C D E", ":ù*$,:!;,"}
	ressourceName := ""
	names := []string{"", "name1", ":ù*$,:!;,"}
	name := ""
	for i := range ressourceNames {
		ressourceName = ressourceNames[i]
		for j := range tests {
			test = tests[j]
			for k := range names {
				name = names[k]
				err := test.caller(ressourceName, name)
				if reflect.TypeOf(err).String() != test.errorType {
					t.Error("Wrong ErrorType Restitution, expect " + test.errorType)
					t.Fail()
				}
				if ressourceName != "" && !strings.Contains(err.Error(), ressourceName) {
					t.Error(fmt.Sprintf("Wrong message restitution, error \"%s\" does not contains ressource name \"%s\", message was \"%s\"", reflect.TypeOf(err).String(), ressourceName, err.Error()))
					t.Fail()
				}
				if name != "" && !strings.Contains(err.Error(), name) {
					t.Error(fmt.Sprintf("Wrong message restitution, error \"%s\" does not contains given name \"%s\", message was \"%s\"", reflect.TypeOf(err).String(), name, err.Error()))
					t.Fail()
				}
			}
		}
	}
}

func TestErrors_ResourceTimeoutError(t *testing.T) {
	expectType := "*fail.ErrTimeout"
	ressourceNames := []string{"", "Ressource1", " A B C D E", ":ù*$,:!;,"}
	ressourceName := ""
	durations := []time.Duration{0 * time.Second, 30 * time.Second, 1 * time.Minute, 30 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	duration := 0 * time.Second
	for i := range ressourceNames {
		ressourceName = ressourceNames[i]
		for j := range durations {
			duration = durations[j]
			err := ResourceTimeoutError(ressourceName, "", duration)
			if reflect.TypeOf(err).String() != expectType {
				t.Error("Wrong ErrorType Restitution, expect " + expectType)
				t.FailNow()
			}
			if ressourceName != "" && !strings.Contains(fmt.Sprintf("%s", err), ressourceName) {
				t.Error("Wrong Message Restitution, error does not contains ressource name \"" + ressourceName + " \"")
				t.FailNow()
			} else {
				if !strings.Contains(fmt.Sprintf("%s", err), fmt.Sprintf("%s", duration)) {
					t.Error("Wrong Message Restitution, error does not contains timeout duration \"" + fmt.Sprintf("%s", duration) + "\"")
					t.FailNow()
				}
			}
		}
	}
}

func TestErrors_IsProvisioningError(t *testing.T) {

	err1 := ResourceNotAvailableError("RessourceType1", "Ressource1")
	err2 := fail.NotAvailableError("RessourceType1 Ressource1 is unavailable, PROVISIONING_ERROR: perhaps ?")

	if IsProvisioningError(err1) {
		t.Error("No, it's not provisioning error")
		t.Fail()
	}
	if !IsProvisioningError(err2) {
		t.Error("No, is it provisioning error")
		t.Fail()
	}
}

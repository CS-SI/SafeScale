/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package aws

import (
    "reflect"

    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// OpContext ...
type OpContext struct {
    ProjectID    string
    DesiredState string
}

// Result ...
type Result struct {
    State string
    Error error
    Done  bool
}

// IPInSubnet ...
type IPInSubnet struct {
    Subnet   string
    Name     string
    ID       string
    IP       string
    PublicIP string
}

func IsOperation(op interface{}, name string, fieldType reflect.Type) bool {
    val := reflect.Indirect(reflect.ValueOf(op))

    result := false

    for i := 0; i < val.Type().NumField(); i++ {

        if val.Type().Field(i).Name == name {
            if val.Type().Field(i).Type == fieldType {
                result = true
                break
            }
        }
    }

    return result
}

func GetOperationStatus(op interface{}, name string, fieldType reflect.Type) (reflect.Value, error) {
    val := reflect.Indirect(reflect.ValueOf(op))

    for i := 0; i < val.Type().NumField(); i++ {

        if val.Type().Field(i).Name == name {
            if val.Type().Field(i).Type == fieldType {
                return reflect.ValueOf(val.Field(i)), nil
            }
        }
    }

    return reflect.Value{}, fail.NotFoundError()
}

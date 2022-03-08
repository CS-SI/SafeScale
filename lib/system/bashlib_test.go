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

package system

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
	"github.com/stretchr/testify/require"
)

func Test_BuildBashLibraryDefinition(t *testing.T) {

	v := temporal.NewTimings()
	result, err := BuildBashLibraryDefinition(v)
	require.EqualValues(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*system.BashLibraryDefinition")

}
func TestBashLibraryDefinition_ToMap(t *testing.T) {

	v := temporal.NewTimings()
	result, err := BuildBashLibraryDefinition(v)
	require.EqualValues(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*system.BashLibraryDefinition")

	m, err := result.ToMap()
	require.EqualValues(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(m).String(), "map[string]interface {}")

}
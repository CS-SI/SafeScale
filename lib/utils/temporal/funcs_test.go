/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package temporal

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_MaxTimeout(t *testing.T) {

	result := MaxTimeout(42*time.Millisecond, 6*time.Second)
	require.EqualValues(t, result, 6*time.Second)

	result = MaxTimeout(18*time.Second, 21*time.Millisecond)
	require.EqualValues(t, result, 18*time.Second)

}

func Test_getFromEnv(t *testing.T) {

	result := getFromEnv(1 * time.Second)
	require.EqualValues(t, result, 1*time.Second)

	result = getFromEnv(2*time.Second, "HOME")
	require.EqualValues(t, result, 2*time.Second)

	os.Setenv("d_test", "4s")

	result = getFromEnv(3*time.Second, "d_test")
	require.EqualValues(t, result, 4*time.Second)

	os.Setenv("d_test", "")

}

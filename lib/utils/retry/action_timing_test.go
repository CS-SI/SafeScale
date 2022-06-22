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

package retry

import (
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/tests"
	"github.com/stretchr/testify/require"
)

func Test_WhileUnsuccessfulWithHardTimeout(t *testing.T) {

	log := tests.LogrusCapture(func() {
		err := WhileUnsuccessfulWithHardTimeout(
			func() error {
				return nil
			},
			800*time.Millisecond,
			400*time.Millisecond,
		)
		require.Nil(t, err)
	})

	require.Contains(t, log, "'delay' greater than 'timeout'")

	err := WhileUnsuccessfulWithHardTimeout(
		func() error {
			return nil
		},
		600*time.Millisecond,
		-1*time.Second,
	)
	require.Nil(t, err)

}

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

package exitcode_test

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/exitcode"
	"github.com/stretchr/testify/require"
)

func TestEnum_String(t *testing.T) {

	require.EqualValues(t, exitcode.OK.String(), "OK")
	require.EqualValues(t, exitcode.Run.String(), "Run")
	require.EqualValues(t, exitcode.InvalidArgument.String(), "InvalidArgument")
	require.EqualValues(t, exitcode.InvalidOption.String(), "InvalidOption")
	require.EqualValues(t, exitcode.InvalidArgument.String(), "InvalidArgument")
	require.EqualValues(t, exitcode.NotFound.String(), "NotFound")
	require.EqualValues(t, exitcode.Timeout.String(), "Timeout")
	require.EqualValues(t, exitcode.RPC.String(), "RPC")
	require.EqualValues(t, exitcode.NotApplicable.String(), "NotApplicable")
	require.EqualValues(t, exitcode.Duplicate.String(), "Duplicate")
	require.EqualValues(t, exitcode.NotImplemented.String(), "NotImplemented")
	require.EqualValues(t, exitcode.Enum(42).String(), "Enum(42)")

}

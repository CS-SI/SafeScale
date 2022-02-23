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

package verdict_test

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/retry/enums/verdict"
	"github.com/stretchr/testify/require"
)

func TestEnum_String(t *testing.T) {

	require.EqualValues(t, verdict.Done.String(), "Done")
	require.EqualValues(t, verdict.Retry.String(), "Retry")
	require.EqualValues(t, verdict.Abort.String(), "Abort")
	require.EqualValues(t, verdict.Undecided.String(), "Undecided")
	require.EqualValues(t, verdict.Enum(42).String(), "Enum(42)")

}

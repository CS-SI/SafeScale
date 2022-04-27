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

package operations

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/stretchr/testify/require"
)

func Test_host_IsNull_Empty(t *testing.T) {
	rh := &Host{}
	itis := valid.IsNil(rh)
	require.True(t, itis)
}

func Test_host_IsNull_Nil(t *testing.T) {
	var rh *Host
	//goland:noinspection GoNilness
	itis := valid.IsNil(rh)
	require.True(t, itis)
}

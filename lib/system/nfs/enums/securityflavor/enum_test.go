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

package securityflavor_test

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/system/nfs/enums/securityflavor"
	"github.com/stretchr/testify/require"
)

func TestEnum_String(t *testing.T) {

	require.EqualValues(t, securityflavor.Sys.String(), "Sys")
	require.EqualValues(t, securityflavor.Krb5.String(), "Krb5")
	require.EqualValues(t, securityflavor.Krb5i.String(), "Krb5i")
	require.EqualValues(t, securityflavor.Krb5p.String(), "Krb5p")
	require.EqualValues(t, securityflavor.Enum(42).String(), "Enum(42)")

}

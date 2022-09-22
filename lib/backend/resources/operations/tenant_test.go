//go:build fixme
// +build fixme

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
	"context"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func Test_CurrentTenant(t *testing.T) {

	tenants, xerr := iaas.GetTenants()
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrSyntax:
			t.Log("No usable tenant found in config, skip test")
			t.SkipNow()
		case *fail.ErrNotFound:
			t.Log("No usable tenant found in config, skip test")
			t.SkipNow()
		default:
			t.Error(xerr)
		}
	}

	require.Nil(t, xerr)
	if len(tenants) == 0 {
		t.Log("No usable tenant found in config, skip test")
		t.SkipNow()
	}

	var (
		found, match      bool
		currentname, name string
	)
	ctx := context.Background()
	tenant := CurrentTenant(ctx)
	match = true
	if tenant != nil {
		currentname = tenant.Name
		match = false
		for _, v := range tenants {
			name, found = v["name"].(string)
			if !found {
				name, found = v["Name"].(string)
			}
			if found {
				if currentname == name {
					match = true
				}
			}
		}
	}
	require.EqualValues(t, match, true)

}

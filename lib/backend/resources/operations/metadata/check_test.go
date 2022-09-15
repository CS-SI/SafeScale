//go:build disabled
// +build disabled

//FIXME: need to move NewServiceTest inside a package
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

package metadata

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func Test_CheckMetadataVersion(t *testing.T) {

	ctx := context.Background()
	err := operations.NewServiceTest(t, func(svc *ServiceTest) {

		var (
			version string
			xerr    fail.Error
		)

		svc._updateOption("version", "")
		svc._updateOption("versionErr", fail.NewError("There is no version"))

		_, xerr = CheckVersion(ctx, svc)
		require.Contains(t, xerr.Error(), "failed to read content of 'version' file in metadata bucket")
		require.Contains(t, xerr.Error(), "There is no version")

		svc._reset()
		svc._updateOption("name", "")
		svc._updateOption("nameErr", fail.NewError("Service has no name"))

		_, xerr = CheckVersion(ctx, svc)
		require.Contains(t, xerr.Error(), "Service has no name")

		svc._reset()
		svc._updateOption("version", "")

		version, xerr = CheckVersion(ctx, svc)
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrForbidden")
		require.EqualValues(t, version, FirstMetadataVersion)

		svc._reset()
		svc._updateOption("version", "v19.00.0")

		version, xerr = CheckVersion(ctx, svc)
		require.EqualValues(t, version, "v19.00.0")
		require.Contains(t, xerr.Error(), "should consider upgrading")

		svc._reset()
		svc._updateOption("version", "v20.06.666")

		version, xerr = CheckVersion(ctx, svc)
		require.Contains(t, xerr.Error(), "should consider upgrading")
		require.EqualValues(t, version, "v20.06.666")

		svc._reset()
		svc._updateOption("version", MinimumMetadataVersion)

		version, xerr = CheckVersion(ctx, svc)
		require.Nil(t, xerr)
		require.EqualValues(t, version, MinimumMetadataVersion)

	})
	require.Nil(t, err)

}

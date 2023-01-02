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

package operations

import (
	"context"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func volumeRequest() abstract.VolumeRequest {
	return abstract.VolumeRequest{
		Name:  "MyVolume",
		Size:  10,
		Speed: volumespeed.Cold,
	}
}

func Test_NewVolume(t *testing.T) {

	var svc iaas.Service
	_, err := NewVolume(svc)
	require.Contains(t, err.Error(), "invalid parameter: svc")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "")
		svc._updateOption("metadatakeyErr", fail.NewError("No metadata key"))

		_, err := NewVolume(svc)
		require.Contains(t, err.Error(), "No metadata key")

		svc._reset()

		volume, err := NewVolume(svc)
		require.Nil(t, err)

		require.EqualValues(t, reflect.TypeOf(volume).String(), "*operations.volume")

	})
	require.Nil(t, xerr)

}

func Test_LoadVolume(t *testing.T) {

	var svc iaas.Service
	ctx := context.Background()

	volume, err := LoadVolume(ctx, svc, "MyVolume")

	require.EqualValues(t, volume, nil)
	require.Contains(t, err.Error(), "invalid parameter: svc")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		volume, xerr := LoadVolume(ctx, svc, "")
		require.EqualValues(t, volume, nil)
		require.Contains(t, xerr.Error(), "cannot be empty string")

		svc._updateOption("getcacheErr", fail.NotFoundError("no cache !"))

		volume, xerr = LoadVolume(ctx, svc, "MyVolume")
		require.EqualValues(t, volume, nil)
		require.Contains(t, xerr.Error(), "neither volumes/byName/MyVolume nor volumes/byID/MyVolume were found in the bucket")

		svc._reset()
		svc._updateOption("timingsErr", fail.NotFoundError("no timings !"))

		_, xerr = svc.CreateVolume(ctx, volumeRequest())
		require.Contains(t, xerr.Error(), "no timings !")

		svc._reset()

		_, xerr = svc.CreateVolume(ctx, volumeRequest())
		require.Nil(t, xerr)

		volume, err := LoadVolume(ctx, svc, "MyVolume")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(volume).String(), "*operations.volume")
		require.EqualValues(t, skip(volume.GetID()), "MyVolume")

	})
	require.Nil(t, xerr)

}

func TestVolume_Create(t *testing.T) {

	var ovolume *volume
	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		volume, err := LoadVolume(ctx, svc, "MyVolume")
		require.EqualValues(t, volume, nil)
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")
		require.Contains(t, err.Error(), "neither volumes/byName/MyVolume nor volumes/byID/MyVolume were found in the bucket")

		xerr := ovolume.Create(ctx, volumeRequest())
		require.Contains(t, xerr.Error(), "calling method from a nil pointer")

		avolume := &abstract.Volume{
			ID:    "MyVolume",
			Name:  "MyVolume",
			Size:  1,
			Speed: volumespeed.Cold,
		}

		mc, xerr := NewCore(svc, "volume", "volumes", avolume)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, avolume)
		require.Nil(t, xerr)

		volume, err = LoadVolume(ctx, svc, "MyVolume")
		require.EqualValues(t, err, nil)
		require.EqualValues(t, reflect.TypeOf(volume).String(), "*operations.volume")
		require.EqualValues(t, skip(volume.GetID()), "MyVolume")

	})
	require.Nil(t, xerr)
}

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

package objectstorage

import (
	"context"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/stretchr/testify/require"
)

func Test_NewMetadataFolder(t *testing.T) {

	mf, xerr := NewFolder(nil, "myfolder")
	require.Contains(t, xerr.Error(), "invalid instance")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")

		mf, xerr = NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(mf).String(), "operations.folder")

		svc._reset()
		svc._updateOption("metadatakey", "")
		svc._updateOption("metadatakeyErr", fail.NotFoundError("No metadatakey"))

		mf, xerr = NewFolder(svc, "myfolder")
		require.Nil(t, xerr) // Return empty one

	})
	require.Nil(t, err)

}

func TestMetadataFolder_IsNull(t *testing.T) {

	var mfa *folder
	require.EqualValues(t, mfa.IsNull(), true)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		require.EqualValues(t, mf.IsNull(), false)
	})
	require.Nil(t, err)

}

func TestMetadataFolder_Service(t *testing.T) {

	var mfa folder
	svca := mfa.Service()
	require.EqualValues(t, valid.IsNil(svca), true)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		require.EqualValues(t, svc, mf.Service())
	})
	require.Nil(t, err)

}

func TestMetadataFolder_GetBucket(t *testing.T) {

	ctx := context.Background()

	var mfa folder
	_, xerr := mfa.GetBucket(ctx)
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		bucket, xerr := mf.GetBucket(ctx)
		require.Nil(t, xerr)
		bucket2, xerr := svc.GetMetadataBucket(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, bucket, bucket2)

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("metadatabucketErr", fail.NewError("Fail to acces to bucket metadata"))

		mf, xerr = NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		_, xerr = mf.GetBucket(ctx)
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")
		_, xerr = mf.getBucket(ctx)
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("metadatabucketErr", fail.NewError("Fail to acces to bucket metadata"))

		mf, xerr = NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		_, xerr = mf.GetBucket(ctx)
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")
		_, xerr = mf.getBucket(ctx)
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")

	})
	require.Nil(t, err)

}

func TestMetadataFolder_Path(t *testing.T) {

	var mfa folder
	path := mfa.Path()
	require.EqualValues(t, path, "")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		path := mf.Path()
		require.EqualValues(t, path, "myfolder")
	})
	require.Nil(t, err)

}

func TestMetadataFolder_Lookup(t *testing.T) {

	ctx := context.Background()

	var mfa folder
	xerr := mfa.Lookup(ctx, "path", "name")
	require.Contains(t, xerr.Error(), "invalid instance")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("metadatabucketErr", fail.NewError("Fail to acces to bucket metadata"))

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		xerr = mf.Lookup(ctx, "path", "name")
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("listobjectsErr", fail.NewError("Fail to list objects"))
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network_Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		xerr = mf.Lookup(ctx, "path", "name")
		require.EqualValues(t, xerr.Error(), "Fail to list objects")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		err = svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network_Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "networks")
		require.Nil(t, xerr)
		xerr = mf.Lookup(ctx, "byName", "Network_Name2")
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrNotFound")

	})
	require.Nil(t, err)

}

func TestMetadataFolder_Delete(t *testing.T) {

	ctx := context.Background()

	var mfa folder
	xerr := mfa.Delete(ctx, "path", "name")
	require.Contains(t, xerr.Error(), "invalid instance")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("metadatabucketErr", fail.NewError("Fail to acces to bucket metadata"))

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		xerr = mf.Delete(ctx, "path", "name")
		require.EqualValues(t, xerr.Error(), "Fail to acces to bucket metadata")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network_Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "networks")
		require.Nil(t, xerr)
		xerr = mf.Delete(ctx, "byName", "Network_Name2")
		require.Nil(t, xerr)
		xerr = mf.Delete(ctx, "byName", "Network_Name")
		require.Nil(t, xerr)
		xerr = mf.Lookup(ctx, "byName", "Network_Name")
		require.EqualValues(t, xerr.Error(), "failed to find metadata 'networks/byName/Network_Name'")

	})
	require.Nil(t, err)

}

func TestMetadataFolder_Read(t *testing.T) {

	ctx := context.Background()

	var mfa folder
	xerr := mfa.Read(ctx, "path", "name", func([]byte) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "invalid instance")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	var callback func(data []byte) fail.Error

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr := NewFolder(svc, "networks")
		require.Nil(t, xerr)
		xerr = mf.Read(ctx, "byName", "Network_Name", callback)
		require.Contains(t, xerr.Error(), "invalid parameter: callback")
		xerr = mf.Read(ctx, "byName", "", func(data []byte) fail.Error {
			return nil
		})
		require.Contains(t, xerr.Error(), "cannot be empty string")
		xerr = mf.Read(ctx, "byName", "Network_Name", func(data []byte) fail.Error {
			str := string(data)
			require.Contains(t, str, "{\"id\":\"Network_ID\",\"name\":\"Network_Name\",\"mask\":\"\",\"tags\":{\"CreationDate\":\"")
			return nil
		})
		require.Contains(t, xerr.Error(), "failed to read 'byName/Network_Name' in Metadata Storage: stopping retries: path \"networks/byName/Network_Name\" not found")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("timingsErr", fail.NewError("No timings !"))
		err = svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "networks")
		require.Nil(t, xerr)
		xerr = mf.Read(ctx, "byName", "Network_Name", func(data []byte) fail.Error {
			return nil
		})
		require.Contains(t, xerr.Error(), "No timings !")

	})
	require.Nil(t, err)

}

func TestMetadataFolder_Write(t *testing.T) {

	ctx := context.Background()
	var mfa folder
	xerr := mfa.Write(ctx, "path", "name", []byte("data"))
	require.Contains(t, xerr.Error(), "invalid instance")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr := NewFolder(svc, "networks")
		require.Nil(t, xerr)
		serial, xerr := network.Serialize()
		require.Nil(t, xerr)
		xerr = mf.Write(ctx, "byID", "", serial)
		require.Contains(t, xerr.Error(), "cannot be empty string")
		xerr = mf.Write(ctx, "byID", "Network_ID", serial)
		require.Nil(t, xerr)
		xerr = mf.Read(ctx, "byID", "Network_ID", func(data []byte) fail.Error {
			require.EqualValues(t, string(serial), string(data))
			return nil
		})
		require.Nil(t, xerr)

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("timingsErr", fail.NewError("No timings !"))
		err = svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "networks")
		require.Nil(t, xerr)
		serial, xerr = network.Serialize()
		require.Nil(t, xerr)
		xerr = mf.Write(ctx, "byID", "", serial)
		require.Contains(t, xerr.Error(), "cannot be empty string")

	})
	require.Nil(t, err)

}

func TestMetadataFolder_Browse(t *testing.T) {

	var mfa folder
	ctx := context.Background()
	xerr := mfa.Browse(ctx, "path", func([]byte) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "invalid instance")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "mykeyhere")
		svc._updateOption("listobjectsErr", fail.NewError("Fail to list objects"))
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr := NewFolder(svc, "myfolder")
		require.Nil(t, xerr)
		xerr = mf.Browse(ctx, "path", func([]byte) fail.Error {
			return nil
		})
		require.Contains(t, xerr.Error(), "Fail to list objects")

		svc._reset()
		svc._updateOption("metadatakey", "mykeyhere")
		err = svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mf, xerr = NewFolder(svc, "networks")
		require.Nil(t, xerr)
		xerr = mf.Browse(ctx, "/", func(data []byte) fail.Error {
			require.Contains(t, string(data), "{\"id\":\"Network_ID\",\"name\":\"Network_Name\",\"mask\":\"\",\"tags\":")
			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

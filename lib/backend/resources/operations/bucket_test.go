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

package operations

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

/*
TODO: unexported type operation.bucket = no acces to test it / break in.
Solve it or give up for cover.
*/
func Test_NewBucket(t *testing.T) {

	var svc iaas.Service

	bucket, err := NewBucket(svc)
	require.Nil(t, bucket)
	require.Contains(t, err.Error(), "cannot be nil")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "")
		svc._updateOption("metadatakeyErr", fail.NewError("No metadata key"))

		bucket, err = NewBucket(svc)
		require.Nil(t, bucket)
		require.Contains(t, err.Error(), "No metadata key")

		svc._reset()

		bucket, err = NewBucket(svc)
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")

	})
	require.Nil(t, xerr)

}

func Test_LoadBucket(t *testing.T) {

	var svc iaas.Service
	ctx := context.Background()

	// Wrong service
	bucket, err := LoadBucket(ctx, svc, "mybucket")
	require.Nil(t, bucket)
	require.Contains(t, err.Error(), "cannot be nil")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		// Load unnamed bucket
		bucket, err = LoadBucket(ctx, svc, "")
		require.Nil(t, bucket)
		require.Contains(t, err.Error(), "cannot be empty string")

		svc._reset()

		// Load not existing bucket
		bucket, err = LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, bucket, nil)
		require.Contains(t, err.Error(), "neither buckets/byName/mybucket nor buckets/byID/mybucket were found in the bucket")

		svc._reset()

		// Bucket, but not a bucket
		network := abstract.NewNetwork()
		network.ID = "Network ID"
		network.Name = "Network Name"

		_ = svc._setInternalData("buckets/byID/notabucket", network)
		_ = svc._setInternalData("buckets/byName/notabucket", network)

		bucket, err = LoadBucket(ctx, svc, "notabucket")
		require.NotNil(t, err)

		svc._reset()

		_, err = svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		svc._updateOption("timingsErr", fail.NotFoundError("no timings !"))

		bucket, err = LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, bucket)
		require.Contains(t, err.Error(), "no timings !")

		svc._reset()

		_, err = svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err = LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")

	})
	require.Nil(t, xerr)

}

func TestBucket_IsNull(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err := LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")
		require.False(t, bucket.IsNull())

	})
	require.Nil(t, xerr)

}

// func TestBucket_Carry(t *testing.T) {} // Private, unreachable

func TestBucket_Browse(t *testing.T) {

	var callback func(storageBucket *abstract.ObjectStorageBucket) fail.Error
	ctx := context.Background()

	task, err := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, err)

	// FIXME: should not panic here
	func() {
		defer func() {
			if r := recover(); r != nil {
				require.Contains(t, fmt.Sprintf("%s", r), "invalid memory address or nil pointer dereference")
			}
		}()
		var bucket resources.Bucket
		_ = bucket.Browse(ctx, func(storageBucket *abstract.ObjectStorageBucket) fail.Error {
			return nil
		})
	}()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err := LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")
		require.False(t, bucket.IsNull())

		xerr := bucket.Browse(nil, func(storageBucket *abstract.ObjectStorageBucket) fail.Error { // nolint
			return nil
		})
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		xerr = bucket.Browse(ctx, callback)
		require.Contains(t, xerr.Error(), "invalid parameter: callback")

		xerr = bucket.Browse(ctx, func(storageBucket *abstract.ObjectStorageBucket) fail.Error {
			require.EqualValues(t, reflect.TypeOf(storageBucket).String(), "*abstract.ObjectStorageBucket")
			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, xerr)

}

// func TestBucket_GetHost(t *testing.T) {} // Private, unreachable

// func TestBucket_GetMountPoint(t *testing.T) {} // Private, unreachable

func TestBucket_Create(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err := LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")
		require.False(t, bucket.IsNull())

		xerr := bucket.Create(ctx, "any")
		require.Contains(t, xerr.Error(), "already carrying information")

	})
	require.Nil(t, xerr)

}

func TestBucket_Delete(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err := LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")
		require.False(t, bucket.IsNull())

		xerr := bucket.Delete(nil) // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		xerr = bucket.Delete(ctx)
		require.Nil(t, xerr)

		xerr = bucket.Delete(ctx)
		require.Contains(t, xerr.Error(), "failed to find Bucket 'mybucket'")

	})
	require.Nil(t, xerr)

}

func TestBucket_Mount(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateBucket(nil, "mybucket")
		require.Nil(t, err)

		bucket, err := LoadBucket(ctx, svc, "mybucket")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*operations.bucket")
		require.False(t, bucket.IsNull())

		xerr := bucket.Mount(nil, "localhost", "buckets/byID/sample") // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		xerr = bucket.Mount(ctx, "", "buckets/byID/sample")
		require.Contains(t, xerr.Error(), "invalid parameter: hostName")

		xerr = bucket.Mount(ctx, "localhost", "")
		require.Contains(t, xerr.Error(), "invalid parameter: path")

		xerr = bucket.Mount(ctx, "localhost", "buckets/byID/sample")
		require.Contains(t, xerr.Error(), "failed to mount bucket 'mybucket' on Host 'localhost'")

		_, _, xerr = svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName: "localhost",
			HostName:     "localhost",
			ImageID:      "ImageID",
			PublicIP:     false,
			Single:       true,
			IsGateway:    true,
			// Subnets:      []*abstract.Subnet{},
			// DefaultRouteIP: request.DefaultRouteIP,
			// DiskSize:       request.DiskSize,
			TemplateID: "TemplateID",
		})
		require.Nil(t, xerr)

		// xerr = bucket.Mount(ctx, "localhost", "buckets/byId/sample")
		// require.EqualValues(t, err.Error(), "unsupported Object Storage protocol 'MyServiceTest-Protocol'")

		// svc._updateOption("protocol", "s3")

		// xerr = bucket.Mount(ctx, "localhost", "buckets/byId/sample")
		// fmt.Println(xerr.Error())

	})
	require.Nil(t, xerr)

}

// func TestBucket_Unmount(t *testing.T) {}

// func TestBucket_ToProtocol(t *testing.T) {} // Private, unreachable

/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package client

import (
	"fmt"
	"sync"
	"time"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// bucket is the part of the safescale client handling buckets
type bucket struct {
	// session is not used currently.
	session *Session
}

// List ...
func (c *bucket) List(timeout time.Duration) (*pb.BucketList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	return service.List(ctx, &google_protobuf.Empty{})
}

// Create ...
func (c *bucket) Create(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Create(ctx, &pb.Bucket{Name: name})
	return err
}

// Delete ...
func (c *bucket) Delete(names []string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	var (
		wg   sync.WaitGroup
		errs int
	)

	bucketDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &pb.Bucket{Name: aname})
		if err != nil {
			fmt.Printf("%v\n", DecorateError(err, "deletion of share", true))
			errs++
		} else {
			fmt.Printf("Share '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go bucketDeleter(target)
	}
	wg.Wait()

	if errs > 0 {
		return clitools.ExitOnRPC("")
	}
	return nil
}

// Inspect ...
func (c *bucket) Inspect(name string, timeout time.Duration) (*pb.BucketMountingPoint, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	return service.Inspect(ctx, &pb.Bucket{Name: name})
}

// Mount ...
func (c *bucket) Mount(bucketName, hostName, mountPoint string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Mount(ctx, &pb.BucketMountingPoint{
		Bucket: bucketName,
		Host: &pb.Reference{
			Name: hostName,
		},
		Path: mountPoint,
	})
	return err
}

// Unmount ...
func (c *bucket) Unmount(bucketName, hostName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewBucketServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Unmount(ctx, &pb.BucketMountingPoint{
		Bucket: bucketName,
		Host:   &pb.Reference{Name: hostName},
	})
	return err
}

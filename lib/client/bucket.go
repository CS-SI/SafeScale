/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
	"sync"
	"time"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// bucket is the part of the safescale client handling buckets
type bucket struct {
	// session is not used currently.
	session *Session
}

// List ...
func (c *bucket) List(timeout time.Duration) (*protocol.BucketList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.List(ctx, &googleprotobuf.Empty{})
}

// Create ...
func (c *bucket) Create(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Create(ctx, &protocol.Bucket{Name: name})
	return err
}

// Delete ...
func (c *bucket) Delete(names []string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	bucketDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &protocol.Bucket{Name: aname})
		if err != nil {
			mutex.Lock()
			errs = append(errs, err.Error())
			mutex.Unlock()
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go bucketDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil
}

// Inspect ...
func (c *bucket) Inspect(name string, timeout time.Duration) (*protocol.BucketMountingPoint, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Inspect(ctx, &protocol.Bucket{Name: name})
}

// Mount ...
func (c *bucket) Mount(bucketName, hostName, mountPoint string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Mount(ctx, &protocol.BucketMountingPoint{
		Bucket: bucketName,
		Host:   &protocol.Reference{Name: hostName},
		Path:   mountPoint,
	})
	return err
}

// Unmount ...
func (c *bucket) Unmount(bucketName, hostName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Unmount(ctx, &protocol.BucketMountingPoint{
		Bucket: bucketName,
		Host:   &protocol.Reference{Name: hostName},
	})
	return err
}

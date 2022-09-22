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

package cmdline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// bucketConsumer is the part of the safescale client handling buckets
type bucketConsumer struct {
	session *Session
}

// List ...
func (c bucketConsumer) List(all bool, timeout time.Duration) (*protocol.BucketListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketListRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		All:          all,
	}
	r, err := service.List(newCtx, req)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Create ...
func (c bucketConsumer) Create(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         name,
	}
	_, err := service.Create(newCtx, req)
	return err
}

// Download ...
func (c bucketConsumer) Download(name string, timeout time.Duration) (*protocol.BucketDownloadResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         name,
	}
	dr, err := service.Download(newCtx, req)
	return dr, err
}

// Clear ...
func (c bucketConsumer) Clear(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         name,
	}
	_, err := service.Clear(newCtx, req)
	return err
}

// Upload ...
func (c bucketConsumer) Upload(name string, dirct string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketUploadRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Bucket:       name,
		Path:         dirct,
	}
	_, err := service.Upload(newCtx, req)
	return err
}

// Delete ...
func (c bucketConsumer) Delete(names []string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	bucketDeleter := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()
		req := &protocol.BucketRequest{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         aname,
		}
		_, err := service.Delete(newCtx, req)
		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go bucketDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil
}

// Inspect ...
func (c bucketConsumer) Inspect(name string, timeout time.Duration) (*protocol.BucketResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketRequest{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         name,
	}
	return service.Inspect(newCtx, req)
}

// Mount ...
func (c bucketConsumer) Mount(bucketName, hostName, mountPoint string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketMountRequest{
		Bucket: bucketName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         hostName,
		},
		Path: mountPoint,
	}
	_, err := service.Mount(newCtx, req)
	return err
}

// Unmount ...
func (c bucketConsumer) Unmount(bucketName, hostName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewBucketServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.BucketMountRequest{
		Bucket: bucketName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         hostName,
		},
	}
	_, err := service.Unmount(newCtx, req)
	return err
}

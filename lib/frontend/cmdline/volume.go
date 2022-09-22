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

// volumeConsumer is the part of safescale client handing volumes
type volumeConsumer struct {
	session *Session
}

// List ...
func (v volumeConsumer) List(all bool, timeout time.Duration) (*protocol.VolumeListResponse, error) {
	v.session.Connect()
	defer v.session.Disconnect()

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

	req := &protocol.VolumeListRequest{
		Organization: v.session.currentOrganization,
		Project:      v.session.currentProject,
		TenantId:     v.session.currentTenant,
		All:          all,
	}
	service := protocol.NewVolumeServiceClient(v.session.connection)
	return service.List(newCtx, req)
}

// Inspect ...
func (v volumeConsumer) Inspect(name string, timeout time.Duration) (*protocol.VolumeInspectResponse, error) {
	v.session.Connect()
	defer v.session.Disconnect()

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

	req := &protocol.Reference{
		Organization: v.session.currentOrganization,
		Project:      v.session.currentProject,
		TenantId:     v.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewVolumeServiceClient(v.session.connection)
	return service.Inspect(newCtx, req)
}

// Delete ...
func (v volumeConsumer) Delete(names []string, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()

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

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewVolumeServiceClient(v.session.connection)

	volumeDeleter := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()

		req := &protocol.Reference{
			Organization: v.session.currentOrganization,
			Project:      v.session.currentProject,
			TenantId:     v.session.currentTenant,
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
		go volumeDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil

}

// Create ...
func (v volumeConsumer) Create(def *protocol.VolumeCreateRequest, timeout time.Duration) (*protocol.VolumeInspectResponse, error) {
	v.session.Connect()
	defer v.session.Disconnect()

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

	def.Organization = v.session.currentOrganization
	def.Project = v.session.currentProject
	def.TenantId = v.session.currentTenant
	service := protocol.NewVolumeServiceClient(v.session.connection)
	return service.Create(newCtx, def)
}

// Attach ...
func (v volumeConsumer) Attach(def *protocol.VolumeAttachmentRequest, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()

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

	def.Volume.Organization = v.session.currentOrganization
	def.Volume.Project = v.session.currentProject
	def.Volume.TenantId = v.session.currentTenant
	service := protocol.NewVolumeServiceClient(v.session.connection)
	_, err := service.Attach(newCtx, def)
	return err
}

// Detach ...
func (v volumeConsumer) Detach(volumeName string, hostName string, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()

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

	req := &protocol.VolumeDetachmentRequest{
		Volume: &protocol.Reference{
			Organization: v.session.currentOrganization,
			Project:      v.session.currentProject,
			TenantId:     v.session.currentTenant,
			Name:         volumeName,
		},
		Host: &protocol.Reference{
			Name: hostName,
		},
	}
	service := protocol.NewVolumeServiceClient(v.session.connection)
	_, err := service.Detach(newCtx, req)
	return err
}

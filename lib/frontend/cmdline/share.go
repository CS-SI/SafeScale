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

package cmdline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// shareConsumer is the part of the safescale client handling Shares
type shareConsumer struct {
	session *Session
}

// Create ...
func (n shareConsumer) Create(def *protocol.ShareCreateRequest, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	def.Host.Organization = n.session.currentOrganization
	def.Host.Project = n.session.currentProject
	def.Host.TenantId = n.session.currentTenant
	service := protocol.NewShareServiceClient(n.session.connection)
	_, err := service.Create(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "creation of share", true)
	}

	return nil
}

// Delete deletes a share
func (n shareConsumer) Delete(names []string, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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
	service := protocol.NewShareServiceClient(n.session.connection)
	shareDeleter := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()

		req := &protocol.Reference{
			Organization: n.session.currentOrganization,
			Project:      n.session.currentProject,
			TenantId:     n.session.currentTenant,
			Name:         aname,
		}
		if _, xerr := service.Delete(newCtx, req); xerr != nil {
			mutex.Lock()
			errs = append(errs, xerr.Error())
			mutex.Unlock() // nolint
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go shareDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}

	return nil
}

// List ...
func (n shareConsumer) List(timeout time.Duration) (*protocol.ShareListResponse, error) {
	n.session.Connect()
	defer n.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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
		Organization: n.session.currentOrganization,
		Project:      n.session.currentProject,
		TenantId:     n.session.currentTenant,
	}
	service := protocol.NewShareServiceClient(n.session.connection)
	list, err := service.List(newCtx, req)
	if err != nil {
		return nil, DecorateTimeoutError(err, "list of shares", true)
	}
	return list, nil
}

// Mount ...
func (n shareConsumer) Mount(def *protocol.ShareMountRequest, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	def.Host.Organization = n.session.currentOrganization
	def.Host.Project = n.session.currentProject
	def.Host.TenantId = n.session.currentTenant
	service := protocol.NewShareServiceClient(n.session.connection)
	_, err := service.Mount(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "mount of share", true)
	}
	return nil
}

// Unmount ...
func (n shareConsumer) Unmount(def *protocol.ShareMountRequest, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	def.Host.Organization = n.session.currentOrganization
	def.Host.Project = n.session.currentProject
	def.Host.TenantId = n.session.currentTenant
	service := protocol.NewShareServiceClient(n.session.connection)
	_, err := service.Unmount(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "unmount of share", true)
	}
	return nil
}

// Inspect ...
func (n shareConsumer) Inspect(name string, timeout time.Duration) (*protocol.ShareMountListResponse, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := common.ContextForGRPC(true)
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
		Organization: n.session.currentOrganization,
		Project:      n.session.currentProject,
		TenantId:     n.session.currentTenant,
		Name:         name,
	}
	list, err := service.Inspect(newCtx, req)
	if err != nil {
		return nil, DecorateTimeoutError(err, "inspection of share", true)
	}
	return list, nil
}
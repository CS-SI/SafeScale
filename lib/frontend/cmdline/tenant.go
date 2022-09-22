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
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// tenantConsumer is the part of safescale client handling tenants
type tenantConsumer struct {
	session *Session
}

// List ...
func (t tenantConsumer) List(timeout time.Duration) (*protocol.TenantList, error) {
	t.session.Connect()
	defer t.session.Disconnect()

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

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.List(newCtx, &emptypb.Empty{})

}

// Get ...
func (t tenantConsumer) Get(timeout time.Duration) (*protocol.TenantNameResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

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

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.Get(newCtx, &emptypb.Empty{})
}

// Set ...
func (t tenantConsumer) Set(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()

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

	service := protocol.NewTenantServiceClient(t.session.connection)
	_, err := service.Set(newCtx, &protocol.TenantInspectRequest{Name: name})
	return err
}

// Inspect ...
func (t tenantConsumer) Inspect(name string, timeout time.Duration) (*protocol.TenantInspectResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure retrieving context")
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.TenantInspectRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		Name:         name,
	}
	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.Inspect(newCtx, req)
}

// Cleanup ...
func (t tenantConsumer) Cleanup(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()

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

	req := &protocol.TenantCleanupRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		Name:         name,
		Force:        false,
	}
	service := protocol.NewTenantServiceClient(t.session.connection)
	_, err := service.Cleanup(newCtx, req)
	return err
}

// Scan ...ScanRequest
func (t tenantConsumer) Scan(name string, dryRun bool, templates []string, timeout time.Duration) (*protocol.ScanResultList, error) {
	t.session.Connect()
	defer t.session.Disconnect()

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

	req := &protocol.TenantScanRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		Name:         name,
		DryRun:       dryRun,
		Templates:    templates,
	}
	service := protocol.NewTenantServiceClient(t.session.connection)
	results, err := service.Scan(newCtx, req)
	return results, err
}

//
// // Upgrade ...
// func (t tenantConsumer) Upgrade(name string, dryRun bool, timeout time.Duration) ([]string, error) {
// 	t.session.Connect()
// 	defer t.session.Disconnect()
//
// 	ctx, xerr := utils.GetContext(true)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	// finally, using context
// 	newCtx := ctx
// 	if timeout != 0 {
// 		aCtx, cancel := context.WithTimeout(ctx, timeout)
// 		defer cancel()
// 		newCtx = aCtx
// 	}
//
// 	service := protocol.NewTenantServiceClient(t.session.connection)
// 	results, err := service.Upgrade(newCtx, &protocol.TenantUpgradeRequest{Name: name, DryRun: dryRun, Force: false})
// 	if results != nil && len(results.Actions) > 0 {
// 		return results.Actions, err
// 	}
// 	return nil, err
// }

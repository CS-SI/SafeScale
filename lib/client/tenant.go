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

package client

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
)

// tenantConsumer is the part of safescale client handling tenants
type tenantConsumer struct {
	// session is not used currently
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
	return service.List(newCtx, &googleprotobuf.Empty{})

}

// Get ...
func (t tenantConsumer) Get(timeout time.Duration) (*protocol.TenantName, error) {
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
	return service.Get(newCtx, &googleprotobuf.Empty{})
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
	_, err := service.Set(newCtx, &protocol.TenantName{Name: name})
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

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.Inspect(newCtx, &protocol.TenantName{Name: name})
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

	service := protocol.NewTenantServiceClient(t.session.connection)
	results, err := service.Scan(newCtx, &protocol.TenantScanRequest{Name: name, DryRun: dryRun, Templates: templates})
	return results, err
}

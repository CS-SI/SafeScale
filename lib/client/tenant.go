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
	"time"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// tenant is the part of safescale client handling tenants
type tenant struct {
	// session is not used currently
	session *Session
}

// List ...
func (t *tenant) List(timeout time.Duration) (*protocol.TenantList, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.List(ctx, &googleprotobuf.Empty{})

}

// Get ...
func (t *tenant) Get(timeout time.Duration) (*protocol.TenantName, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.Get(ctx, &googleprotobuf.Empty{})
}

// Set ...
func (t *tenant) Set(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewTenantServiceClient(t.session.connection)
	_, err := service.Set(ctx, &protocol.TenantName{Name: name})
	return fail.ToError(err)
}

// Inspect ...
func (t *tenant) Inspect(name string, timeout time.Duration) (*protocol.TenantInspectResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewTenantServiceClient(t.session.connection)
	return service.Inspect(ctx, &protocol.TenantName{Name: name})
}

// Cleanup ...
func (t *tenant) Cleanup(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewTenantServiceClient(t.session.connection)
	_, err := service.Cleanup(ctx, &protocol.TenantCleanupRequest{Name: name, Force: false})
	return err
}

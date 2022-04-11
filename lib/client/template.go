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

package client

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/utils"
)

// host is the safescale client part handling hosts
type template struct {
	// session is not used currently
	session *Session
}

// List returns the list of available templates on the current tenant
func (t template) List(all, scannedOnly bool, timeout time.Duration) (*protocol.TemplateList, error) {
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

	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.List(newCtx, &protocol.TemplateListRequest{All: all, ScannedOnly: scannedOnly})
}

// Match returns the list of templates that match the sizing
func (t template) Match(sizing string, timeout time.Duration) (*protocol.TemplateList, error) {
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

	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.Match(newCtx, &protocol.TemplateMatchRequest{Sizing: sizing})
}

// Inspect returns details of a template identified by name of ID
func (t template) Inspect(name string, timeout time.Duration) (*protocol.HostTemplate, error) {
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

	service := protocol.NewTemplateServiceClient(t.session.connection)

	return service.Inspect(newCtx, &protocol.TemplateInspectRequest{Template: &protocol.Reference{Name: name}})
}

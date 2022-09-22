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

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
)

// templateConsumer is the safescale client part handling templates
type templateConsumer struct {
	session *Session
}

// List returns the list of available templates on the current templates
func (t templateConsumer) List(all, scannedOnly bool, timeout time.Duration) (*protocol.TemplateList, error) {
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

	req := &protocol.TemplateListRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		TenantId:     t.session.currentTenant,
		All:          all,
		ScannedOnly:  scannedOnly,
	}
	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.List(newCtx, req)
}

// Match returns the list of templates that match the sizing
func (t templateConsumer) Match(sizing string, timeout time.Duration) (*protocol.TemplateList, error) {
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

	req := &protocol.TemplateMatchRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		TenantId:     t.session.currentTenant,
		Sizing:       sizing,
	}
	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.Match(newCtx, req)
}

// Inspect returns details of a template identified by name of ID
func (t templateConsumer) Inspect(name string, timeout time.Duration) (*protocol.HostTemplate, error) {
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

	req := &protocol.TemplateInspectRequest{
		Template: &protocol.Reference{
			Organization: t.session.currentOrganization,
			Project:      t.session.currentProject,
			TenantId:     t.session.currentTenant,
			Name:         name,
		},
	}
	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.Inspect(newCtx, req)
}

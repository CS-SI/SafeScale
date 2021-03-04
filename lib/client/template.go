/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
)

// host is the safescale client part handling hosts
type template struct {
	// session is not used currently
	session *Session
}

// List return the list of availble templates on the current tenant
func (t template) List(all bool, timeout time.Duration) (*protocol.TemplateList, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.List(ctx, &protocol.TemplateListRequest{All: all})
}

// Inspect return the list of available template information on the current tenant
func (t template) Inspect(all bool, onlyScanned bool, timeout time.Duration) (*protocol.TemplateList, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewTemplateServiceClient(t.session.connection)
	return service.Inspect(ctx, &protocol.TemplateInspectRequest{All: all, OnlyScanned: onlyScanned})
}

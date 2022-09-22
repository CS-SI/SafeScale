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

// imageConsumer is the safescale client part handling images
type imageConsumer struct {
	session *Session
}

// List return the list of available images of currentTenant
func (img imageConsumer) List(all bool, timeout time.Duration) (*protocol.ImageList, error) {
	img.session.Connect()
	defer img.session.Disconnect()

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

	req := &protocol.ImageListRequest{
		Organization: img.session.currentOrganization,
		Project:      img.session.currentProject,
		TenantId:     img.session.currentTenant,
		All:          all,
	}
	service := protocol.NewImageServiceClient(img.session.connection)
	return service.List(newCtx, req)
}

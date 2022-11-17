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

	"github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
)

// jobConsumer is the part of the safescale client handling jobs
type jobConsumer struct {
	session *Session
}

// List ...
func (c jobConsumer) List(timeout time.Duration) (*protocol.JobList, error) {
	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(false)
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

	service := protocol.NewJobServiceClient(c.session.connection)
	return service.List(newCtx, &emptypb.Empty{})
}

// Stop sends a signal to the currentServer to stop a running job
func (c jobConsumer) Stop(uuid string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(false)
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

	req := &protocol.JobDefinition{Uuid: uuid}
	service := protocol.NewJobServiceClient(c.session.connection)
	_, err := service.Stop(newCtx, req)
	return err
}
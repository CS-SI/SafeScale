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
)

// bucket is the part of the safescale client handling buckets
type jobManager struct {
	// session is not used currently.
	session *Session
}

// List ...
func (c *jobManager) List(timeout time.Duration) (*protocol.JobList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewJobServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(false)
	if xerr != nil {
		return nil, xerr
	}

	return service.List(ctx, &googleprotobuf.Empty{})
}

// Stop sends a signal to the server to stop a running job
func (c *jobManager) Stop(uuid string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewJobServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(false)
	if xerr != nil {
		return xerr
	}

	_, err := service.Stop(ctx, &protocol.JobDefinition{Uuid: uuid})
	return err
}

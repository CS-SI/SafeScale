/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// bucket is the part of the broker client handling buckets
type processManager struct {
	// session is not used currently.
	session *Session
}

// List ...
func (c *processManager) List(timeout time.Duration) (*pb.ProcessList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewProcessManagerServiceClient(c.session.connection)
	ctx := utils.GetContext(false)

	return service.List(ctx, &google_protobuf.Empty{})
}

// Stop ...
func (c *processManager) Stop(uuid string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewProcessManagerServiceClient(c.session.connection)
	ctx := utils.GetContext(false)

	_, err := service.Stop(ctx, &pb.ProcessDefinition{UUID: uuid})
	return err
}

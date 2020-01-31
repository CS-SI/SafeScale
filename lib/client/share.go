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

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/utils"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// share is the part of the safescale client handilng Shares
type share struct {
	session *Session
}

// Create ...
func (n *share) Create(def pb.ShareDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Create(ctx, &def)
	if err != nil {
		return DecorateError(err, "creation of share", true)
	}
	return nil
}

// Delete deletes a share
func (n *share) Delete(name string, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Delete(ctx, &pb.Reference{Name: name})
	if err != nil {
		return DecorateError(err, "deletion of share", true)
	}
	return nil
}

// List ...
func (n *share) List(timeout time.Duration) (*pb.ShareList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	list, err := service.List(ctx, &googleprotobuf.Empty{})
	if err != nil {
		return nil, DecorateError(err, "list of shares", true)
	}
	return list, nil
}

// Mount ...
func (n *share) Mount(def pb.ShareMountDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Mount(ctx, &def)
	if err != nil {
		return DecorateError(err, "mount of share", true)
	}
	return nil
}

// Unmount ...
func (n *share) Unmount(def pb.ShareMountDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Unmount(ctx, &def)
	if err != nil {
		return DecorateError(err, "unmount of share", true)
	}
	return nil
}

// Inspect ...
func (n *share) Inspect(name string, timeout time.Duration) (*pb.ShareMountList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewShareServiceClient(n.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	list, err := service.Inspect(ctx, &pb.Reference{Name: name})
	if err != nil {
		return nil, DecorateError(err, "inspection of share", true)
	}
	return list, nil
}

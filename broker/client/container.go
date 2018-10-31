/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	utils "github.com/CS-SI/SafeScale/broker/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// container is the part of the broker client handling containers
// VPL: shouldn't it be called Bucket ? Container will conflict with Docker synonym...
type container struct {
	// session is not used currently.
	session *Session
}

// List ...
func (c *container) List(timeout time.Duration) (*pb.ContainerList, error) {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	return service.List(ctx, &google_protobuf.Empty{})
}

// Create ...
func (c *container) Create(name string, timeout time.Duration) error {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	_, err := service.Create(ctx, &pb.Container{Name: name})
	return err
}

// Delete ...
func (c *container) Delete(name string, timeout time.Duration) error {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	_, err := service.Delete(ctx, &pb.Container{Name: name})
	return err
}

// Inspect ...
func (c *container) Inspect(name string, timeout time.Duration) (*pb.ContainerMountingPoint, error) {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	return service.Inspect(ctx, &pb.Container{Name: name})
}

// Mount ...
func (c *container) Mount(containerName, hostName, mountPoint string, timeout time.Duration) error {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	_, err := service.Mount(ctx, &pb.ContainerMountingPoint{
		Container: containerName,
		Host: &pb.Reference{
			Name: hostName,
		},
		Path: mountPoint,
	})
	return err
}

// Unmount ...
func (c *container) Unmount(containerName, hostName string, timeout time.Duration) error {
	conn := utils.GetConnection(int(c.session.brokerdPort))
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewContainerServiceClient(conn)
	_, err := service.UMount(ctx, &pb.ContainerMountingPoint{
		Container: containerName,
		Host:      &pb.Reference{Name: hostName},
	})
	return err
}

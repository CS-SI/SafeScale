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
	"github.com/CS-SI/SafeScale/broker/utils"
)

// network is the part of broker client handling Network
type network struct {
	// session is not used currently
	session *Session
}

// List ...
func (n *network) List(all bool, timeout time.Duration) (*pb.NetworkList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	return networkService.List(ctx, &pb.NWListRequest{
		All: all,
	})
}

// Delete ...
func (n *network) Delete(name string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	_, err := networkService.Delete(ctx, &pb.Reference{Name: name})
	return err
}

// Inspect ...
func (n *network) Inspect(name string, timeout time.Duration) (*pb.Network, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	return networkService.Inspect(ctx, &pb.Reference{Name: name})
}

// Create ...
func (n *network) Create(def pb.NetworkDefinition, timeout time.Duration) (*pb.Network, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	return networkService.Create(ctx, &def)
}

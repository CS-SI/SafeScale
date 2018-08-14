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

// tenant is the part of broker client handling tenants
type tenant struct{}

// List ...
func (t *tenant) List(timeout time.Duration) (*pb.TenantList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	tenantService := pb.NewTenantServiceClient(conn)
	return tenantService.List(ctx, &google_protobuf.Empty{})
}

// Get ...
func (t *tenant) Get(timeout time.Duration) (*pb.TenantName, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	tenantService := pb.NewTenantServiceClient(conn)
	return tenantService.Get(ctx, &google_protobuf.Empty{})
}

// Set ...
func (t *tenant) Set(name string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	tenantService := pb.NewTenantServiceClient(conn)
	_, err := tenantService.Set(ctx, &pb.TenantName{Name: name})
	return err
}

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

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// tenant is the part of safescale client handling tenants
type tenant struct {
	// session is not used currently
	session *Session
}

// List ...
func (t *tenant) List(timeout time.Duration) (*pb.TenantList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	return service.List(ctx, &google_protobuf.Empty{})

}

// Get ...
func (t *tenant) Get(timeout time.Duration) (*pb.TenantName, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	return service.Get(ctx, &google_protobuf.Empty{})
}

// Set ...
func (t *tenant) Set(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Set(ctx, &pb.TenantName{Name: name})
	return err
}

// StorageList ...
func (t *tenant) StorageList(timeout time.Duration) (*pb.TenantList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	return service.StorageList(ctx, &google_protobuf.Empty{})
}

// StorageGet ...
func (t *tenant) StorageGet(timeout time.Duration) (*pb.TenantNameList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	return service.StorageGet(ctx, &google_protobuf.Empty{})
}

// StorageSet ...
func (t *tenant) StorageSet(names []string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.StorageSet(ctx, &pb.TenantNameList{Names: names})
	return err
}

/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/utils"
)

// tenant is the part of safescale client handling tenants
type tenant struct {
	session *Session
}

// List ...
func (t *tenant) List(timeout time.Duration) (*pb.TenantList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.List(ctx, &googleprotobuf.Empty{})
}

func (t *tenant) Inspect(all bool, timeout time.Duration) (*pb.ResourceList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	reslist, err := service.Inspect(ctx, &pb.TenantInspectRequest{All: all})
	if err != nil {
		return nil, err
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		if reslist != nil {
			logrus.Warnf("error inspecting tennant: %s", spew.Sdump(reslist.String()))
		}
	}
	return reslist, err
}

// Get ...
func (t *tenant) Get(timeout time.Duration) (*pb.TenantName, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Get(ctx, &googleprotobuf.Empty{})
}

// Set ...
func (t *tenant) Set(name string, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTenantServiceClient(t.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Set(ctx, &pb.TenantName{Name: name})
	return err
}

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
	"github.com/CS-SI/SafeScale/lib/server/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// data is the part of the safescale client handling erasure-coded data
type data struct {
	// session is not used currently.
	session *Session
}

// Push uploads a file to storage tenants.
func (c *data) Push(localFilePath string, fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Push(ctx, &pb.File{LocalPath: localFilePath, Name: fileName})
	return err
}

// Pull downloads a file from storage tenants.
func (c *data) Pull(localFilePath string, fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Pull(ctx, &pb.File{LocalPath: localFilePath, Name: fileName})
	return err
}

// List returns a list of files in storage tenants.
func (c *data) List(timeout time.Duration) (*pb.FileList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.List(ctx, &google_protobuf.Empty{})

}

// Delete deletes a file from storage tenants.
func (c *data) Delete(fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Delete(ctx, &pb.File{Name: fileName})
	return err
}

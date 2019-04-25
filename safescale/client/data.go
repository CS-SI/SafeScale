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

	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// bucket is the part of the safescale client handling buckets
type data struct {
	// session is not used currently.
	session *Session
}

// Push ...
func (c *data) Push(localFilePath string, fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Push(ctx, &pb.File{LocalPath: localFilePath, Name: fileName})
	return err
}

// Get ...
func (c *data) Get(localFilePath string, fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Get(ctx, &pb.File{LocalPath: localFilePath, Name: fileName})
	return err
}

// List ...
func (c *data) List(timeout time.Duration) (*pb.FileList, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	return service.List(ctx, &google_protobuf.Empty{})

}

// Delete ...
func (c *data) Delete(fileName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := pb.NewDataServiceClient(c.session.connection)
	ctx := utils.GetContext(true)

	_, err := service.Delete(ctx, &pb.File{Name: fileName})
	return err
}

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
	"fmt"
	"sync"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	utils "github.com/CS-SI/SafeScale/broker/utils"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// share is the part of the broker client handing Shares
type share struct {
	// Session is not used currently
	session *Session
}

// Create ...
func (n *share) Create(def pb.ShareDefinition, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewShareServiceClient(conn)

	_, err := service.Create(ctx, &def)
	return err
}

// Delete deletes several nas at the same time in goroutines
func (n *share) Delete(names []string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}

	timeout = timeout + (30 * time.Second * time.Duration(len(names)))

	var wg sync.WaitGroup

	shareDeleter := func(aname string) {
		defer wg.Done()
		ctx, cancel := utils.GetContext(timeout)
		defer cancel()
		shareService := pb.NewShareServiceClient(conn)
		_, err := shareService.Delete(ctx, &pb.Reference{Name: aname})

		if err != nil {
			fmt.Println(DecorateError(err, "deletion of share", true).Error())
		} else {
			fmt.Printf("Share '%s' successfully deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go shareDeleter(target)
	}
	wg.Wait()

	return nil
}

// List ...
func (n *share) List(timeout time.Duration) (*pb.ShareList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewShareServiceClient(conn)
	return service.List(ctx, &google_protobuf.Empty{})
}

// Mount ...
func (n *share) Mount(def pb.ShareMountDefinition, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewShareServiceClient(conn)
	_, err := service.Mount(ctx, &def)
	return err
}

// Unmount ...
func (n *share) Unmount(def pb.ShareMountDefinition, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewShareServiceClient(conn)
	_, err := service.Unmount(ctx, &def)
	return err
}

// Inspect ...
func (n *share) Inspect(name string, timeout time.Duration) (*pb.ShareList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewShareServiceClient(conn)
	return service.Inspect(ctx, &pb.Reference{Name: name})
}

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

// nas is the part of the broker client handing Nas
// VPL: shouldn't it be called 'share' ?
type nas struct {
	// Session is not used currently
	session *Session
}

// Create ...
func (n *nas) Create(def pb.NasDefinition, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewNasServiceClient(conn)

	_, err := service.Create(ctx, &def)
	return err
}

// Delete deletes several nas at the same time in goroutines
func (n *nas) Delete(names []string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}

	timeout = timeout + (30 * time.Second * time.Duration(len(names)))

	var wg sync.WaitGroup

	nasDeleter := func(aname string) {
		defer wg.Done()
		ctx, cancel := utils.GetContext(timeout)
		defer cancel()
		nasService := pb.NewNasServiceClient(conn)
		_, err := nasService.Delete(ctx, &pb.NasName{Name: aname})

		if err != nil {
			fmt.Printf("Error response from daemon : %v", DecorateError(err, "deletion of Nas", true))
		} else {
			fmt.Printf("Nas '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go nasDeleter(target)
	}

	wg.Wait()

	return nil
}

// List ...
func (n *nas) List(timeout time.Duration) (*pb.NasList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewNasServiceClient(conn)
	return service.List(ctx, &google_protobuf.Empty{})
}

// Mount ...
func (n *nas) Mount(nasName, hostName, mountPoint string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewNasServiceClient(conn)
	def := pb.NasDefinition{
		Nas:  &pb.NasName{Name: nasName},
		Host: &pb.Reference{Name: hostName},
		Path: mountPoint,
	}

	_, err := service.Mount(ctx, &def)
	return err
}

// Unmount ...
func (n *nas) Unmount(nasName, hostName string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewNasServiceClient(conn)
	_, err := service.UMount(ctx, &pb.NasDefinition{
		Nas:  &pb.NasName{Name: nasName},
		Host: &pb.Reference{Name: hostName},
	})
	return err
}

// Inspect ...
func (n *nas) Inspect(name string, timeout time.Duration) (*pb.NasList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewNasServiceClient(conn)
	return service.Inspect(ctx, &pb.NasName{
		Name: name,
	})
}

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
	"github.com/CS-SI/SafeScale/broker/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// network is the part of broker client handling Network
type network struct {
	// session is not used currently
	session *Session
}

// List ...
func (n *network) List(all bool, timeout time.Duration) (*pb.NetworkList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewNetworkServiceClient(n.session.connection)
	ctx := utils.GetContext(true)

	return service.List(ctx, &pb.NWListRequest{
		All: all,
	})
}

// TODO concurent access if deleting multiple networks
// Delete deletes several networks at the same time in goroutines
func (n *network) Delete(names []string, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewNetworkServiceClient(n.session.connection)
	ctx := utils.GetContext(true)

	var (
		wg   sync.WaitGroup
		errs int
	)

	networkDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &pb.Reference{Name: aname})

		if err != nil {
			fmt.Println(DecorateError(err, "deletion of network", true).Error())
			errs++
		} else {
			fmt.Printf("Network '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go networkDeleter(target)
	}
	wg.Wait()

	if errs > 0 {
		return clitools.ExitOnRPC("")
	}
	return nil

}

// Inspect ...
func (n *network) Inspect(name string, timeout time.Duration) (*pb.Network, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewNetworkServiceClient(n.session.connection)
	ctx := utils.GetContext(true)

	return service.Inspect(ctx, &pb.Reference{Name: name})

}

// Create ...
func (n *network) Create(def pb.NetworkDefinition, timeout time.Duration) (*pb.Network, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := pb.NewNetworkServiceClient(n.session.connection)
	ctx := utils.GetContext(true)

	return service.Create(ctx, &def)

}

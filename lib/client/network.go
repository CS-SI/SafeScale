/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// networkConsumer is the part of safescale client handling Networking
type networkConsumer struct {
	// session is not used currently
	session *Session
}

// List ...
func (n networkConsumer) List(all bool, timeout time.Duration) (*protocol.NetworkList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	return service.List(newCtx, &protocol.NetworkListRequest{
		All: all,
	})
}

var forceCtxKey = "force"

// Delete deletes several networks at the same time in goroutines
func (n networkConsumer) Delete(names []string, timeout time.Duration, force bool) error { // TODO: concurrent access if deleting multiple networks
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := context.WithValue(ctx, &forceCtxKey, force) // nolint
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	networkDeleter := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()
		_, err := service.Delete(newCtx, &protocol.NetworkDeleteRequest{
			Network: &protocol.Reference{Name: aname},
			Force:   force,
		})

		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go networkDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil

}

// Inspect ...
func (n networkConsumer) Inspect(name string, timeout time.Duration) (*protocol.Network, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	return service.Inspect(newCtx, &protocol.Reference{Name: name})

}

// Create calls the gRPC server to create a network
func (n networkConsumer) Create(
	name, cidr string,
	noSubnet bool,
	gwname string, gwSSHPort uint32, os, sizing string,
	keepOnFailure bool,
	timeout time.Duration,
) (*protocol.Network, error) {

	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	def := &protocol.NetworkCreateRequest{
		Name:          name,
		Cidr:          cidr,
		NoSubnet:      noSubnet,
		KeepOnFailure: keepOnFailure,
		Gateway: &protocol.GatewayDefinition{
			Name:           gwname,
			SshPort:        gwSSHPort,
			ImageId:        os,
			SizingAsString: sizing,
		},
	}
	return service.Create(newCtx, def)
}

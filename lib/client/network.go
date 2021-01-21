/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// network is the part of safescale client handling Networking
type network struct {
	// session is not used currently
	session *Session
}

// List ...
func (n network) List(all bool, timeout time.Duration) (*protocol.NetworkList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	return service.List(ctx, &protocol.NetworkListRequest{
		All: all,
	})
}

// TODO concurent access if deleting multiple networks
// Delete deletes several networks at the same time in goroutines
func (n network) Delete(names []string, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	networkDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &protocol.Reference{Name: aname})

		if err != nil {
			mutex.Lock()
			errs = append(errs, err.Error())
			mutex.Unlock()
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
func (n network) Inspect(name string, timeout time.Duration) (*protocol.Network, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewNetworkServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	return service.Inspect(ctx, &protocol.Reference{Name: name})

}

// Create calls the gRPC server to create a network
func (n network) Create(
	name, cidr string,
	noSubnet bool,
	gwname string, defaultSshPort uint32, os, sizing string,
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

	def := &protocol.NetworkCreateRequest{
		Name:          name,
		Cidr:          cidr,
		NoSubnet:      noSubnet,
		KeepOnFailure: keepOnFailure,
		Gateway: &protocol.GatewayDefinition{
			Name:    gwname,
			SshPort: defaultSshPort,
			ImageId: os,
		},
	}
	return service.Create(ctx, def)
}

//// BindSecurityGroup calls the gRPC server to bind a security group to a network
//func (n network) BindSecurityGroup(networkRef, sgRef string, enable bool, duration time.Duration) error {
//	n.session.Connect()
//	defer n.session.Disconnect()
//
//	ctx, xerr := utils.GetContext(true)
//	if xerr != nil {
//		return xerr
//	}
//
//	req := &protocol.SecurityGroupBindRequest{
//		Group:  &protocol.Reference{Name: sgRef},
//		Target: &protocol.Reference{Name: networkRef},
//		Enable: enable,
//	}
//	service := protocol.NewNetworkServiceClient(n.session.connection)
//	_, err := service.BindSecurityGroup(ctx, req)
//	return err
//}
//
//// UnbindSecurityGroup calls the gRPC server to unbind a security group from a network
//func (n network) UnbindSecurityGroup(networkRef, sgRef string, duration time.Duration) error {
//	n.session.Connect()
//	defer n.session.Disconnect()
//
//	ctx, xerr := utils.GetContext(true)
//	if xerr != nil {
//		return xerr
//	}
//
//	req := &protocol.SecurityGroupBindRequest{
//		Group:  &protocol.Reference{Name: sgRef},
//		Target: &protocol.Reference{Name: networkRef},
//	}
//	service := protocol.NewHostServiceClient(n.session.connection)
//	_, err := service.UnbindSecurityGroup(ctx, req)
//	return err
//}
//
//// EnableSecurityGroup calls the gRPC server to enable a bound security group of a network
//func (n network) EnableSecurityGroup(networkRef, sgRef string, duration time.Duration) error {
//	n.session.Connect()
//	defer n.session.Disconnect()
//
//	ctx, xerr := utils.GetContext(true)
//	if xerr != nil {
//		return xerr
//	}
//
//	req := &protocol.SecurityGroupBindRequest{
//		Group:  &protocol.Reference{Name: sgRef},
//		Target: &protocol.Reference{Name: networkRef},
//	}
//	service := protocol.NewNetworkServiceClient(n.session.connection)
//	_, err := service.EnableSecurityGroup(ctx, req)
//	return err
//}
//
//// DisableSecurityGroup calls the gRPC server to disable a bound security group of a network
//func (n network) DisableSecurityGroup(networkRef, sgRef string, duration time.Duration) error {
//	n.session.Connect()
//	defer n.session.Disconnect()
//
//	ctx, xerr := utils.GetContext(true)
//	if xerr != nil {
//		return xerr
//	}
//
//	service := protocol.NewNetworkServiceClient(n.session.connection)
//
//	req := &protocol.SecurityGroupBindRequest{
//		Group:  &protocol.Reference{Name: sgRef},
//		Target: &protocol.Reference{Name: networkRef},
//	}
//	_, err := service.DisableSecurityGroup(ctx, req)
//	return err
//}
//
//// ListSecurityGroups calls the gRPC server to list bound security groups of a network
//func (n network) ListSecurityGroups(networkRef, kind string, duration time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
//	n.session.Connect()
//	defer n.session.Disconnect()
//
//	ctx, xerr := utils.GetContext(true)
//	if xerr != nil {
//		return nil, xerr
//	}
//
//	service := protocol.NewNetworkServiceClient(n.session.connection)
//
//	req := &protocol.SecurityGroupBondsRequest{
//		Target: &protocol.Reference{Name: networkRef},
//		Kind:   strings.ToLower(kind),
//	}
//	return service.ListSecurityGroups(ctx, req)
//}

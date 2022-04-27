/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
)

// subnet is the part of safescale client handling Subnets
type subnet struct {
	// session is not used currently
	session *Session
}

// List ...
// FIXME: do not use protocol as response
func (s subnet) List(networkRef string, all bool, timeout time.Duration) (*protocol.SubnetList, error) {
	s.session.Connect()
	defer s.session.Disconnect()
	service := protocol.NewSubnetServiceClient(s.session.connection)
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

	return service.List(newCtx, &protocol.SubnetListRequest{
		Network: &protocol.Reference{Name: networkRef},
		All:     all,
	})
}

// Delete deletes several networks at the same time in goroutines
func (s subnet) Delete(networkRef string, names []string, timeout time.Duration, force bool) error {
	s.session.Connect()
	defer s.session.Disconnect()
	service := protocol.NewSubnetServiceClient(s.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	valCtx := context.WithValue(ctx, &forceCtxKey, force) // nolint
	newCtx, cancel := context.WithTimeout(valCtx, timeout)
	defer cancel()

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	subnetDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(newCtx, &protocol.SubnetDeleteRequest{
			Network: &protocol.Reference{Name: networkRef},
			Subnet:  &protocol.Reference{Name: aname},
			Force:   true,
		})

		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go subnetDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil

}

// Inspect ...
func (s subnet) Inspect(networkRef, name string, timeout time.Duration) (*protocol.Subnet, error) {
	s.session.Connect()
	defer s.session.Disconnect()
	service := protocol.NewSubnetServiceClient(s.session.connection)
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

	req := &protocol.SubnetInspectRequest{
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: name},
	}
	return service.Inspect(newCtx, req)

}

// Create calls the gRPC server to create a network
// FIXME: do not use protocol as parameter to client method
// FIXME: do not use protocol as response
func (s subnet) Create(
	networkRef, name, cidr string, failover bool,
	gwname string, gwport uint32, os, sizing string,
	keepOnFailure bool,
	timeout time.Duration,
) (*protocol.Subnet, error) {

	s.session.Connect()
	defer s.session.Disconnect()
	service := protocol.NewSubnetServiceClient(s.session.connection)
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

	def := &protocol.SubnetCreateRequest{
		Name:     name,
		Cidr:     cidr,
		Network:  &protocol.Reference{Name: networkRef},
		FailOver: failover,
		Gateway: &protocol.GatewayDefinition{
			ImageId:        os,
			Name:           gwname,
			SshPort:        gwport,
			SizingAsString: sizing,
		},
		KeepOnFailure: keepOnFailure,
	}
	return service.Create(newCtx, def)
}

// BindSecurityGroup calls the gRPC server to bind a security group to a network
func (s subnet) BindSecurityGroup(networkRef, subnetRef, sgRef string, enable bool, timeout time.Duration) error {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	var state protocol.SecurityGroupState
	switch enable {
	case false:
		state = protocol.SecurityGroupState_SGS_DISABLED
	case true:
		state = protocol.SecurityGroupState_SGS_ENABLED
	}
	req := &protocol.SecurityGroupSubnetBindRequest{
		Group:   &protocol.Reference{Name: sgRef},
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: subnetRef},
		State:   state,
	}
	service := protocol.NewSubnetServiceClient(s.session.connection)
	_, err := service.BindSecurityGroup(newCtx, req)
	return err
}

// UnbindSecurityGroup calls the gRPC server to unbind a security group from a network
func (s subnet) UnbindSecurityGroup(networkRef, subnetRef, sgRef string, timeout time.Duration) error {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.SecurityGroupSubnetBindRequest{
		Group:   &protocol.Reference{Name: sgRef},
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: subnetRef},
	}
	service := protocol.NewSubnetServiceClient(s.session.connection)
	_, err := service.UnbindSecurityGroup(newCtx, req)
	return err
}

// EnableSecurityGroup calls the gRPC server to enable a bound security group of a network
func (s subnet) EnableSecurityGroup(networkRef, subnetRef, sgRef string, timeout time.Duration) error {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.SecurityGroupSubnetBindRequest{
		Group:   &protocol.Reference{Name: sgRef},
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: subnetRef},
	}
	service := protocol.NewSubnetServiceClient(s.session.connection)
	_, err := service.EnableSecurityGroup(newCtx, req)
	return err
}

// DisableSecurityGroup calls the gRPC server to disable a bound security group of a network
func (s subnet) DisableSecurityGroup(networkRef, subnetRef, sgRef string, timeout time.Duration) error {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	service := protocol.NewSubnetServiceClient(s.session.connection)

	req := &protocol.SecurityGroupSubnetBindRequest{
		Group:   &protocol.Reference{Name: sgRef},
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: subnetRef},
	}
	_, err := service.DisableSecurityGroup(newCtx, req)
	return err
}

// ListSecurityGroups calls the gRPC server to list bound security groups of a network
// FIXME: do not use protocol as response
func (s subnet) ListSecurityGroups(networkRef, subnetRef, state string, timeout time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
	s.session.Connect()
	defer s.session.Disconnect()

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

	service := protocol.NewSubnetServiceClient(s.session.connection)

	req := &protocol.SecurityGroupSubnetBindRequest{
		Network: &protocol.Reference{Name: networkRef},
		Subnet:  &protocol.Reference{Name: subnetRef},
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "all":
		req.State = protocol.SecurityGroupState_SGS_ALL
	case "enable", "enabled":
		req.State = protocol.SecurityGroupState_SGS_ENABLED
	case "disable", "disabled":
		req.State = protocol.SecurityGroupState_SGS_DISABLED
	default:
		return nil, fail.SyntaxError("invalid value '%s' for 'state' field", state)
	}

	return service.ListSecurityGroups(newCtx, req)
}

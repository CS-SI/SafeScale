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

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
)

// var sshCfgCache = cache.NewMapCache()

// securityGroup is the SafeScale client part handling security groups
type securityGroup struct {
	// session is not used currently
	session *Session
}

// List ...
func (sg securityGroup) List(all bool, timeout time.Duration) (*protocol.SecurityGroupListResponse, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	rv, err := service.List(newCtx, &protocol.SecurityGroupListRequest{All: all})
	if err != nil {
		return nil, err
	}
	return rv, nil
}

// Inspect ...
func (sg securityGroup) Inspect(ref string, timeout time.Duration) (*protocol.SecurityGroupResponse, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	rv, err := service.Inspect(newCtx, &protocol.Reference{Name: ref})
	if err != nil {
		return nil, err
	}
	return rv, nil
}

// Create creates a new security group
func (sg securityGroup) Create(networkRef string, req abstract.SecurityGroup, timeout time.Duration) (*abstract.SecurityGroup, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	protoRequest := &protocol.SecurityGroupCreateRequest{
		Network:     &protocol.Reference{Name: networkRef},
		Name:        req.Name,
		Description: req.Description,
		Rules:       converters.SecurityGroupRulesFromAbstractToProtocol(req.Rules),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	resp, err := service.Create(newCtx, protoRequest)
	if err != nil {
		return nil, err
	}

	rv, err := converters.SecurityGroupFromProtocolToAbstract(resp)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

// Delete deletes several hosts at the same time in goroutines
func (sg securityGroup) Delete(names []string, force bool, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	taskDeleteSecurityGroup := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()
		req := &protocol.SecurityGroupDeleteRequest{
			Group: &protocol.Reference{Name: aname},
			Force: force,
		}
		_, err := service.Delete(newCtx, req)
		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go taskDeleteSecurityGroup(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil
}

// Clear ...
func (sg securityGroup) Clear(ref string, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.Clear(newCtx, &protocol.Reference{Name: ref})
	if err != nil {
		return err
	}
	return nil
}

// Reset ...
func (sg securityGroup) Reset(ref string, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.Reset(newCtx, &protocol.Reference{Name: ref})
	if err != nil {
		return err
	}
	return nil
}

// AddRule ...
func (sg securityGroup) AddRule(group string, rule *abstract.SecurityGroupRule, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	req := &protocol.SecurityGroupRuleRequest{
		Group: &protocol.Reference{Name: group},
		Rule:  converters.SecurityGroupRuleFromAbstractToProtocol(rule),
	}
	_, err := service.AddRule(newCtx, req)
	if err != nil {
		return err
	}
	return nil
}

// DeleteRule ...
func (sg securityGroup) DeleteRule(group string, rule *abstract.SecurityGroupRule, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	def := &protocol.SecurityGroupRuleDeleteRequest{
		Group: &protocol.Reference{Name: group},
		Rule:  converters.SecurityGroupRuleFromAbstractToProtocol(rule),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.DeleteRule(newCtx, def)
	if err != nil {
		return err
	}
	return nil
}

// Bonds ...
func (sg securityGroup) Bonds(group, kind string, timeout time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

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

	req := &protocol.SecurityGroupBondsRequest{
		Target: &protocol.Reference{Name: group},
		Kind:   strings.ToLower(kind),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	rv, err := service.Bonds(newCtx, req)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// var sshCfgCache = cache.NewMapCache()

// securityGroup is the safescale client part handling security groups
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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	return service.List(ctx, &protocol.SecurityGroupListRequest{All: all})
}

// Inspect ...
func (sg securityGroup) Inspect(ref string, timeout time.Duration) (*protocol.SecurityGroupResponse, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	return service.Inspect(ctx, &protocol.Reference{Name: ref})
}

// Create creates a new security group
func (sg securityGroup) Create(networkRef string, req abstract.SecurityGroup, timeout time.Duration) (abstract.SecurityGroup, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

	nullSg := abstract.SecurityGroup{}

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nullSg, xerr
	}

	protoRequest := &protocol.SecurityGroupCreateRequest{
		Network:     &protocol.Reference{Name: networkRef},
		Name:        req.Name,
		Description: req.Description,
		Rules:       converters.SecurityGroupRulesFromAbstractToProtocol(req.Rules),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	resp, err := service.Create(ctx, protoRequest)
	if err != nil {
		return nullSg, err
	}

	return converters.SecurityGroupFromProtocolToAbstract(resp)
}

// Delete deletes several hosts at the same time in goroutines
func (sg securityGroup) Delete(names []string, force bool, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	taskDeleteSecurityGroup := func(aname string) {
		defer wg.Done()
		req := &protocol.SecurityGroupDeleteRequest{
			Group: &protocol.Reference{Name: aname},
			Force: force,
		}
		_, err := service.Delete(ctx, req)
		if err != nil {
			mutex.Lock()
			errs = append(errs, err.Error())
			mutex.Unlock()
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

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.Clear(ctx, &protocol.Reference{Name: ref})
	return err
}

// Reset ...
func (sg securityGroup) Reset(ref string, timeout time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.Reset(ctx, &protocol.Reference{Name: ref})
	return err
}

// AddRule ...
func (sg securityGroup) AddRule(group string, rule abstract.SecurityGroupRule, duration time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	req := &protocol.SecurityGroupRuleRequest{
		Group: &protocol.Reference{Name: group},
		Rule:  converters.SecurityGroupRuleFromAbstractToProtocol(rule),
	}
	_, err := service.AddRule(ctx, req)
	return err
}

// DeleteRule ...
func (sg securityGroup) DeleteRule(group string, rule abstract.SecurityGroupRule, duration time.Duration) error {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	def := &protocol.SecurityGroupRuleDeleteRequest{
		Group: &protocol.Reference{Name: group},
		Rule:  converters.SecurityGroupRuleFromAbstractToProtocol(rule),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	_, err := service.DeleteRule(ctx, def)
	return err
}

// Bonds ...
func (sg securityGroup) Bonds(group, kind string, duration time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
	sg.session.Connect()
	defer sg.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	req := &protocol.SecurityGroupBondsRequest{
		Target: &protocol.Reference{Name: group},
		Kind:   strings.ToLower(kind),
	}
	service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
	return service.Bonds(ctx, req)
}

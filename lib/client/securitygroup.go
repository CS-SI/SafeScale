/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
func (sg securityGroup) Create(req *protocol.SecurityGroupRequest, timeout time.Duration) (*protocol.SecurityGroupResponse, error) {
    sg.session.Connect()
    defer sg.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return nil, xerr
    }

    service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
    return service.Create(ctx, req)
}

// Delete deletes several hosts at the same time in goroutines
func (sg securityGroup) Delete(names []string, timeout time.Duration) error {
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
        _, err := service.Delete(ctx, &protocol.Reference{Name: aname})
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

    service := protocol.NewHostServiceClient(sg.session.connection)
    return service.Clear(ctx, &protocol.Reference{Name: ref})
}

// Reset ...
func (sg securityGroup) Reset(ref string, timeout time.Duration) error {
    sg.session.Connect()
    defer sg.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return xerr
    }

    service := protocol.NewHostServiceClient(sg.session.connection)
    return service.Reset(ctx, &protocol.Reference{Name: ref})
}

// AddRule ...
func (sg securityGroup) AddRule(def *protocol.SecurityGroupRuleRequest, duration time.Duration) error {
    sg.session.Connect()
    defer sg.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return xerr
    }

    service := protocol.NewSecurityGroupServiceClient(sg.session.connection)
    return service.AddRule(ctx, def)
}

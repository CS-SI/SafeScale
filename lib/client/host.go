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
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// var sshCfgCache = cache.NewMapCache()

// host is the safescale client part handling hosts
type host struct {
	// session is not used currently
	session *Session
}

// List ...
func (h host) List(all bool, timeout time.Duration) (*protocol.HostList, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	return service.List(ctx, &protocol.HostListRequest{All: all})
}

// Inspect ...
func (h host) Inspect(name string, timeout time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Inspect(ctx, &protocol.Reference{Name: name})
}

// GetStatus gets host status
func (h host) GetStatus(name string, timeout time.Duration) (*protocol.HostStatus, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Status(ctx, &protocol.Reference{Name: name})
}

// Reboot host
func (h host) Reboot(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.Reboot(ctx, &protocol.Reference{Name: name})
	return err
}

// Start host
func (h host) Start(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.Start(ctx, &protocol.Reference{Name: name})
	return err
}

// Stop host
func (h host) Stop(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := protocol.NewHostServiceClient(h.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	_, err := service.Stop(ctx, &protocol.Reference{Name: name})
	return err
}

// Create creates a new host
func (h host) Create(req *protocol.HostDefinition, timeout time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Create(ctx, req)
}

// Delete deletes several hosts at the same time in goroutines
func (h host) Delete(names []string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewHostServiceClient(h.session.connection)
	hostDeleter := func(aname string) {
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
		go hostDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil
}

// SSHConfig ...
func (h host) SSHConfig(name string) (*system.SSHConfig, error) {
	// if anon, ok := sshCfgCache.Get(name); ok {
	// 	return anon.(*system.SSHConfig), nil
	// }

	h.session.Connect()
	defer h.session.Disconnect()
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	pbSSHCfg, err := service.SSH(ctx, &protocol.Reference{Name: name})
	if err != nil {
		return nil, err
	}
	sshCfg := converters.SSHConfigFromProtocolToSystem(pbSSHCfg)
	// if err == nil {
	// 	nerr := sshCfgCache.Set(name, sshCfg)
	// 	if nerr != nil {
	// 		return sshCfg, nerr
	// 	}
	// }
	return sshCfg, err
}

// Resize ...
func (h host) Resize(def *protocol.HostDefinition, duration time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Resize(ctx, def)
}

// ListFeatures ...
func (h host) ListFeatures(hostRef string, all bool, duration time.Duration) (*protocol.FeatureListResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	req := protocol.FeatureListRequest{
		TargetType:    protocol.FeatureTargetType_FT_HOST,
		TargetRef:     &protocol.Reference{Name: hostRef},
		InstalledOnly: !all,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	result, err := service.List(ctx, &req)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// CheckFeatures ...
func (h host) CheckFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef:  &protocol.Reference{Name: hostRef},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Check(ctx, req)
	return fail.ToError(err)
}

// AddFeature ...
func (h host) AddFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef:  &protocol.Reference{Name: hostRef},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Add(ctx, req)
	return err
}

// RemoveFeature ...
func (h host) RemoveFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef:  &protocol.Reference{Name: hostRef},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Remove(ctx, req)
	return err
}

// BindSecurityGroup calls the gRPC server to bind a security group to a host
func (h host) BindSecurityGroup(hostRef, sgRef string, enable bool, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.SecurityGroupBindRequest{
		Group:  &protocol.Reference{Name: sgRef},
		Target: &protocol.Reference{Name: hostRef},
		Enable: enable,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.BindSecurityGroup(ctx, req)
	return err
}

// UnbindSecurityGroup calls the gRPC server to unbind a security group from a host
func (h host) UnbindSecurityGroup(hostRef, sgRef string, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.SecurityGroupBindRequest{
		Group:  &protocol.Reference{Name: sgRef},
		Target: &protocol.Reference{Name: hostRef},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.UnbindSecurityGroup(ctx, req)
	return err
}

// EnableSecurityGroup calls the gRPC server to enable a bound security group on host
func (h host) EnableSecurityGroup(hostRef, sgRef string, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.SecurityGroupBindRequest{
		Group:  &protocol.Reference{Name: sgRef},
		Target: &protocol.Reference{Name: hostRef},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.EnableSecurityGroup(ctx, req)
	return err
}

// DisableSecurityGroup calls the gRPC server to disable a bound security group on host
func (h host) DisableSecurityGroup(hostRef, sgRef string, duration time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.SecurityGroupBindRequest{
		Group:  &protocol.Reference{Name: sgRef},
		Target: &protocol.Reference{Name: hostRef},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.DisableSecurityGroup(ctx, req)
	return err
}

// ListSecurityGroups calls the gRPC server to list bound security groups of a network
func (h host) ListSecurityGroups(hostRef, kind string, duration time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(h.session.connection)

	req := &protocol.SecurityGroupBondsRequest{
		Target: &protocol.Reference{Name: hostRef},
		Kind:   strings.ToLower(kind),
	}
	return service.ListSecurityGroups(ctx, req)
}

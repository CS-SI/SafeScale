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

package cmdline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// var sshCfgCache = cache.NewMapCache()

// hostConsumer is the safescale client part handling hosts
type hostConsumer struct {
	session *Session
}

// List ...
func (h hostConsumer) List(all bool, timeout time.Duration) (*protocol.HostList, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.HostListRequest{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		All:          all,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.List(newCtx, req)
}

// Inspect ...
func (h hostConsumer) Inspect(name string, timeout time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Inspect(newCtx, req)
}

// GetStatus gets host status
func (h hostConsumer) GetStatus(name string, timeout time.Duration) (*protocol.HostStatus, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Status(newCtx, req)
}

// Reboot host
func (h hostConsumer) Reboot(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.Reboot(newCtx, req)
	return err
}

// Start host
func (h hostConsumer) Start(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.Start(newCtx, req)
	return err
}

// Stop host
func (h hostConsumer) Stop(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := protocol.NewHostServiceClient(h.session.connection)
	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	_, err := service.Stop(newCtx, req)
	return err
}

// Create creates a new host
func (h hostConsumer) Create(req *protocol.HostCreateRequest, timeout time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req.Organization = h.session.currentOrganization
	req.Project = h.session.currentProject
	req.TenantId = h.session.currentTenant
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Create(newCtx, req)
}

// Delete deletes several hosts at the same time in goroutines
func (h hostConsumer) Delete(names []string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	service := protocol.NewHostServiceClient(h.session.connection)
	hostDeleter := func(aname string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()

		req := &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         aname,
		}
		_, xerr := service.Delete(newCtx, req)
		if xerr != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, xerr.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go hostDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil
}

// SSHConfig ...
func (h hostConsumer) SSHConfig(name string) (sshapi.Config, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return nil, xerr
	}

	req := &protocol.Reference{
		Organization: h.session.currentOrganization,
		Project:      h.session.currentProject,
		TenantId:     h.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	pbSSHCfg, err := service.SSH(ctx, req)
	if err != nil {
		return nil, err
	}

	sshCfg := converters.SSHConfigFromProtocolToSystem(pbSSHCfg)

	return sshCfg, err
}

// Resize ...
func (h hostConsumer) Resize(def *protocol.HostCreateRequest, timeout time.Duration) (*protocol.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	def.Organization = h.session.currentOrganization
	def.Project = h.session.currentProject
	def.TenantId = h.session.currentTenant
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.Resize(newCtx, def)
}

// ListFeatures ...
func (h hostConsumer) ListFeatures(hostRef string, all bool, timeout time.Duration) (*protocol.FeatureListResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := protocol.FeatureListRequest{
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		InstalledOnly: !all,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	result, err := service.List(newCtx, &req)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// InspectFeature ...
func (h hostConsumer) InspectFeature(hostRef, featureName string, embedded bool, timeout time.Duration) (*protocol.FeatureDetailResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.FeatureDetailRequest{
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		Name:     featureName,
		Embedded: embedded,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	return service.Inspect(newCtx, req)
}

// ExportFeature ...
func (h hostConsumer) ExportFeature(hostRef, featureName string, embedded bool, timeout time.Duration) (*protocol.FeatureExportResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.FeatureDetailRequest{
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		Name:     featureName,
		Embedded: embedded,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	return service.Export(newCtx, req)
}

// CheckFeature ...
func (h hostConsumer) CheckFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		Variables: params,
		Settings:  settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Check(newCtx, req)
	return err
}

// AddFeature ...
func (h hostConsumer) AddFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		Variables: params,
		Settings:  settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Add(newCtx, req)
	return err
}

// RemoveFeature ...
func (h hostConsumer) RemoveFeature(hostRef, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_HOST,
		TargetRef: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
		Variables: params,
		Settings:  settings,
	}
	service := protocol.NewFeatureServiceClient(h.session.connection)
	_, err := service.Remove(newCtx, req)
	return err
}

// BindSecurityGroup calls the gRPC currentServer to bind a security group to a host
func (h hostConsumer) BindSecurityGroup(hostRef, sgRef string, enable bool, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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
	case true:
		state = protocol.SecurityGroupState_SGS_ENABLED
	case false:
		state = protocol.SecurityGroupState_SGS_DISABLED
	}
	req := &protocol.SecurityGroupHostBindRequest{
		Group: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         sgRef,
		},
		Host: &protocol.Reference{
			Name: hostRef,
		},
		State: state,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.BindSecurityGroup(newCtx, req)
	return err
}

// UnbindSecurityGroup calls the gRPC currentServer to unbind a security group from a host
func (h hostConsumer) UnbindSecurityGroup(hostRef, sgRef string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.SecurityGroupHostBindRequest{
		Group: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         sgRef,
		},
		Host: &protocol.Reference{
			Name: hostRef,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.UnbindSecurityGroup(newCtx, req)
	return err
}

// EnableSecurityGroup calls the gRPC currentServer to enable a bound security group on host
func (h hostConsumer) EnableSecurityGroup(hostRef, sgRef string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.SecurityGroupHostBindRequest{
		Group: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         sgRef,
		},
		Host: &protocol.Reference{
			Name: hostRef,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.EnableSecurityGroup(newCtx, req)
	return err
}

// DisableSecurityGroup calls the gRPC currentServer to disable a bound security group on host
func (h hostConsumer) DisableSecurityGroup(hostRef, sgRef string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.SecurityGroupHostBindRequest{
		Group: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         sgRef,
		},
		Host: &protocol.Reference{
			Name: hostRef,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.DisableSecurityGroup(newCtx, req)
	return err
}

// ListSecurityGroups calls the gRPC currentServer to list bound security groups of a host
func (h hostConsumer) ListSecurityGroups(hostRef, state string, timeout time.Duration) (*protocol.SecurityGroupBondsResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.SecurityGroupHostBindRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostRef,
		},
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
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.ListSecurityGroups(newCtx, req)
}

// ListLabels lists Labels bound to Host
func (h hostConsumer) ListLabels(hostName string, selectTags bool, timeout time.Duration) (*protocol.LabelListResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	service := protocol.NewHostServiceClient(h.session.connection)
	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.LabelBoundsRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Tags: selectTags,
	}
	return service.ListLabels(newCtx, req)
}

// InspectLabel to Host
func (h hostConsumer) InspectLabel(hostName string, labelName string, timeout time.Duration) (*protocol.HostLabelResponse, error) {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.HostLabelRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Label: &protocol.Reference{
			Name: labelName,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	return service.InspectLabel(newCtx, req)
}

// BindLabel to Host
func (h hostConsumer) BindLabel(hostName string, labelName string, value string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.LabelBindRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Label: &protocol.Reference{
			Name: labelName,
		},
		Value: value,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.BindLabel(newCtx, req)
	return err
}

// UnbindLabel from Host
func (h hostConsumer) UnbindLabel(hostName string, labelName string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.LabelBindRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Label: &protocol.Reference{
			Name: labelName,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.UnbindLabel(newCtx, req)
	return err
}

// UpdateLabel to Host
func (h hostConsumer) UpdateLabel(hostName string, labelName string, value string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	req := &protocol.LabelBindRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Label: &protocol.Reference{
			Name: labelName,
		},
		Value: value,
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.UpdateLabel(newCtx, req)
	return err
}

// ResetLabel from Host
func (h hostConsumer) ResetLabel(hostName string, labelName string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
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

	// FIXME: recover tenantConsumer ID from current session
	req := &protocol.LabelBindRequest{
		Host: &protocol.Reference{
			Organization: h.session.currentOrganization,
			Project:      h.session.currentProject,
			TenantId:     h.session.currentTenant,
			Name:         hostName,
		},
		Label: &protocol.Reference{
			Name: labelName,
		},
	}
	service := protocol.NewHostServiceClient(h.session.connection)
	_, err := service.ResetLabel(newCtx, req)
	return err
}

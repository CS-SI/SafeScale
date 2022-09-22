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

package cmdline

import (
	"context"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// var sshCfgCache = cache.NewMapCache()

// clusterConsumer is the safescale client part handling clusters
type clusterConsumer struct {
	session *Session
}

// List ...
func (c clusterConsumer) List(timeout time.Duration) (*protocol.ClusterListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewClusterServiceClient(c.session.connection)
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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
	}
	result, err := service.List(newCtx, req)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Inspect ...
func (c clusterConsumer) Inspect(clusterName string, timeout time.Duration) (*protocol.ClusterResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}

	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	result, err := service.Inspect(newCtx, req)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetState gets cluster status
func (c clusterConsumer) GetState(clusteName string, timeout time.Duration) (*protocol.ClusterStateResponse, error) {
	if clusteName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusteName")
	}

	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusteName,
	}
	return service.State(newCtx, req)
}

// Start starts all the hosts of the cluster
func (c clusterConsumer) Start(clusterName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	_, err := service.Start(newCtx, req)
	return err
}

// Stop stops all the hosts of the cluster
func (c clusterConsumer) Stop(clusterName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	_, err := service.Stop(newCtx, req)
	return err
}

// Create ...
func (c clusterConsumer) Create(def *protocol.ClusterCreateRequest, timeout time.Duration) (*protocol.ClusterResponse, error) {
	if def == nil {
		return nil, fail.InvalidParameterCannotBeNilError("def")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewClusterServiceClient(c.session.connection)
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

	def.Organization = c.session.currentOrganization
	def.Project = c.session.currentProject
	def.TenantId = c.session.currentTenant
	cr, zerr := service.Create(newCtx, def)
	if zerr != nil {
		return nil, zerr
	}
	return cr, nil
}

// Delete deletes a cluster
func (c clusterConsumer) Delete(clusterName string, force bool, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	service := protocol.NewClusterServiceClient(c.session.connection)
	req := &protocol.ClusterDeleteRequest{
		Name:         clusterName,
		Force:        force,
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
	}
	_, err := service.Delete(newCtx, req)
	return err
}

// Expand ...
func (c clusterConsumer) Expand(req *protocol.ClusterResizeRequest, timeout time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if req == nil {
		return nil, fail.InvalidParameterCannotBeNilError("req")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	service := protocol.NewClusterServiceClient(c.session.connection)
	req.Organization = c.session.currentOrganization
	req.Project = c.session.currentProject
	req.TenantId = c.session.currentTenant
	return service.Expand(newCtx, req)
}

// Shrink ...
func (c clusterConsumer) Shrink(req *protocol.ClusterResizeRequest, timeout time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if req == nil {
		return nil, fail.InvalidParameterCannotBeNilError("req")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	service := protocol.NewClusterServiceClient(c.session.connection)
	req.Organization = c.session.currentOrganization
	req.Project = c.session.currentProject
	req.TenantId = c.session.currentTenant
	return service.Shrink(newCtx, req)
}

// CheckFeature ...
func (c clusterConsumer) CheckFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if featureName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		Variables: params,
		Settings:  settings,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Check(newCtx, req)
	return err
}

// AddFeature ...
func (c clusterConsumer) AddFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if featureName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	c.session.Connect()
	defer c.session.Disconnect()
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		Variables: params,
		Settings:  settings,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Add(newCtx, req)
	return err
}

// RemoveFeature ...
func (c clusterConsumer) RemoveFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterError("clusterName", "cannot be empty string")
	}
	if featureName == "" {
		return fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.FeatureActionRequest{
		Name:       featureName,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		Variables: params,
		Settings:  settings,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Remove(newCtx, req)
	return err
}

// ListFeatures ...
func (c clusterConsumer) ListFeatures(clusterName string, all bool, timeout time.Duration) (*protocol.FeatureListResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	request := &protocol.FeatureListRequest{
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		InstalledOnly: !all,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	list, err := service.List(newCtx, request)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// InspectFeature ...
func (c clusterConsumer) InspectFeature(clusterName, featureName string, embedded bool, timeout time.Duration) (*protocol.FeatureDetailResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	req := &protocol.FeatureDetailRequest{
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		Name:     featureName,
		Embedded: embedded,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	list, err := service.Inspect(newCtx, req)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// ExportFeature recovers content of the feature file and returns it
func (c clusterConsumer) ExportFeature(clusterName, featureName string, embedded bool, timeout time.Duration) (*protocol.FeatureExportResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewFeatureServiceClient(c.session.connection)
	req := &protocol.FeatureDetailRequest{
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         clusterName,
		},
		Name:     featureName,
		Embedded: embedded,
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	list, err := service.Export(newCtx, req)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// FindAvailableMaster ...
func (c clusterConsumer) FindAvailableMaster(clusterName string, timeout time.Duration) (*protocol.Host, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	host, err := service.FindAvailableMaster(newCtx, req)
	if err != nil {
		return nil, err
	}
	return host, nil
}

// ListNodes ...
func (c clusterConsumer) ListNodes(clusterName string, timeout time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	list, err := service.ListNodes(newCtx, req)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// InspectNode ...
func (c clusterConsumer) InspectNode(clusterName string, nodeRef string, timeout time.Duration) (*protocol.Host, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         nodeRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.InspectNode(newCtx, req)
}

// DeleteNode ...
func (c clusterConsumer) DeleteNode(clusterName string, nodes []string, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if len(nodes) == 0 {
		return fail.InvalidParameterError("nodes", "cannot be an empty slice")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	service := protocol.NewClusterServiceClient(c.session.connection)

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	nodeDeleter := func(ref string) {
		var crash error
		defer fail.SilentOnPanic(&crash)

		defer wg.Done()

		req := &protocol.ClusterNodeRequest{
			Name: clusterName, Host: &protocol.Reference{
				Organization: c.session.currentOrganization,
				Project:      c.session.currentProject,
				TenantId:     c.session.currentTenant,
				Name:         ref,
			},
		}
		_, err := service.DeleteNode(newCtx, req)
		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	if len(nodes) > 1 {
		// We want to check first if currentTenant is set when there are more than 1 node, to avoid multiple message claiming there is no tenantConsumer set...
		tenantService := protocol.NewTenantServiceClient(c.session.connection)
		_, err := tenantService.Get(newCtx, &emptypb.Empty{})
		if err != nil {
			return err
		}
	}

	wg.Add(len(nodes))
	for _, target := range nodes {
		go nodeDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}

	return nil
}

// StartNode ...
func (c clusterConsumer) StartNode(clusterName string, nodeRef string, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         nodeRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StartNode(newCtx, req)
	return err
}

// StopNode ...
func (c clusterConsumer) StopNode(clusterName string, nodeRef string, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         nodeRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StopNode(newCtx, req)
	return err
}

// StateNode ...
func (c clusterConsumer) StateNode(clusterName string, nodeRef string, timeout time.Duration) (*protocol.HostStatus, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         nodeRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.StateNode(newCtx, req)
}

// ListMasters ...
func (c clusterConsumer) ListMasters(clusterName string, timeout time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.Reference{
		Organization: c.session.currentOrganization,
		Project:      c.session.currentProject,
		TenantId:     c.session.currentTenant,
		Name:         clusterName,
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	list, err := service.ListMasters(newCtx, req)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// InspectMaster ...
func (c clusterConsumer) InspectMaster(clusterName string, masterRef string, timeout time.Duration) (*protocol.Host, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         masterRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.InspectMaster(newCtx, req)
}

// StartMaster ...
func (c clusterConsumer) StartMaster(clusterName string, masterRef string, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         masterRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StartMaster(newCtx, req)
	return err
}

// StopMaster ...
func (c clusterConsumer) StopMaster(clusterName string, masterRef string, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Name:         masterRef,
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StopMaster(newCtx, req)
	return err
}

// StateMaster ...
func (c clusterConsumer) StateMaster(clusterName string, masterRef string, timeout time.Duration) (*protocol.HostStatus, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	c.session.Connect()
	defer c.session.Disconnect()

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

	req := &protocol.ClusterNodeRequest{
		Name: clusterName,
		Host: &protocol.Reference{
			Organization: c.session.currentOrganization,
			Project:      c.session.currentProject,
			TenantId:     c.session.currentTenant,
			Name:         masterRef,
		},
	}
	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.StateMaster(newCtx, req)
}

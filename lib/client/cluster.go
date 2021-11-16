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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// var sshCfgCache = cache.NewMapCache()

// host is the safescale client part handling hosts
type cluster struct {
	// session is not used currently
	session *Session
}

// List ...
func (c cluster) List(timeout time.Duration) (*protocol.ClusterListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()

	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	result, err := service.List(ctx, &protocol.Reference{})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Inspect ...
func (c cluster) Inspect(clusterName string, timeout time.Duration) (*protocol.ClusterResponse, error) {
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

	result, err := service.Inspect(ctx, &protocol.Reference{Name: clusterName})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetState gets cluster status
func (c cluster) GetState(clusteName string, timeout time.Duration) (*protocol.ClusterStateResponse, error) {
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

	return service.State(ctx, &protocol.Reference{Name: clusteName})
}

// Start starts all the hosts of the cluster
func (c cluster) Start(clusterName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	_, err := service.Start(ctx, &protocol.Reference{Name: clusterName})
	return err
}

// Stop stops all the hosts of the cluster
func (c cluster) Stop(clusterName string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	_, err := service.Stop(ctx, &protocol.Reference{Name: clusterName})
	return err
}

// Create ...
func (c cluster) Create(def *protocol.ClusterCreateRequest, timeout time.Duration) (*protocol.ClusterResponse, error) {
	if def == nil {
		return nil, fail.InvalidParameterCannotBeNilError("def")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.Create(ctx, def)
}

// Delete deletes a cluster
func (c cluster) Delete(clusterName string, force bool, timeout time.Duration) error {
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	req := &protocol.ClusterDeleteRequest{
		Name:  clusterName,
		Force: force,
	}
	_, err := service.Delete(ctx, req)
	return err
}

// Expand ...
func (c cluster) Expand(req *protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if req == nil {
		return nil, fail.InvalidParameterCannotBeNilError("req")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.Expand(ctx, req)
}

// Shrink ...
func (c cluster) Shrink(req *protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if req == nil {
		return nil, fail.InvalidParameterCannotBeNilError("req")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.Shrink(ctx, req)
}

// CheckFeature ...
func (c cluster) CheckFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
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
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Check(ctx, req)
	return err
}

// AddFeature ...
func (c cluster) AddFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
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
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Add(ctx, req)
	return err
}

// RemoveFeature ...
func (c cluster) RemoveFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
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
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   settings,
	}
	service := protocol.NewFeatureServiceClient(c.session.connection)
	_, err := service.Remove(ctx, req)
	return err
}

// ListInstalledFeatures ...
func (c cluster) ListInstalledFeatures(clusterName string, all bool, duration time.Duration) (*protocol.FeatureListResponse, error) {
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
		TargetType:    protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef:     &protocol.Reference{Name: clusterName},
		InstalledOnly: !all,
	}
	list, err := service.List(ctx, request)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// FindAvailableMaster ...
func (c cluster) FindAvailableMaster(clusterName string, duration time.Duration) (*protocol.Host, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	host, err := service.FindAvailableMaster(ctx, &protocol.Reference{Name: clusterName})
	if err != nil {
		return nil, err
	}
	return host, nil
}

// ListNodes ...
func (c cluster) ListNodes(clusterName string, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	list, err := service.ListNodes(ctx, &protocol.Reference{Name: clusterName})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// InspectNode ...
func (c cluster) InspectNode(clusterName string, nodeRef string, duration time.Duration) (*protocol.Host, error) {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.InspectNode(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: nodeRef}})
}

// DeleteNode ...
func (c cluster) DeleteNode(clusterName string, nodes []string, duration time.Duration) error {
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

	service := protocol.NewClusterServiceClient(c.session.connection)

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	nodeDeleter := func(ref string) {
		defer wg.Done()

		if _, err := service.DeleteNode(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: ref}}); err != nil {
			mutex.Lock()
			errs = append(errs, err.Error())
			mutex.Unlock()
		}
	}

	if len(nodes) > 1 {
		// We want to check first if tenant is set when there are more than 1 node, to avoid multiple message claiming there is no tenant set...
		tenantService := protocol.NewTenantServiceClient(c.session.connection)
		_, err := tenantService.Get(ctx, &googleprotobuf.Empty{})
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
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}

	return nil
}

// StartNode ...
func (c cluster) StartNode(clusterName string, nodeRef string, duration time.Duration) error {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StartNode(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: nodeRef}})
	return err
}

// StopNode ...
func (c cluster) StopNode(clusterName string, nodeRef string, duration time.Duration) error {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StopNode(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: nodeRef}})
	return err
}

// StateNode ...
func (c cluster) StateNode(clusterName string, nodeRef string, duration time.Duration) (*protocol.HostStatus, error) {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.StateNode(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: nodeRef}})
}

// ListMasters ...
func (c cluster) ListMasters(clusterName string, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewClusterServiceClient(c.session.connection)
	list, err := service.ListMasters(ctx, &protocol.Reference{Name: clusterName})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// InspectMaster ...
func (c cluster) InspectMaster(clusterName string, masterRef string, duration time.Duration) (*protocol.Host, error) {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.InspectMaster(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: masterRef}})
}

// StartMaster ...
func (c cluster) StartMaster(clusterName string, masterRef string, duration time.Duration) error {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StartMaster(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: masterRef}})
	return err
}

// StopMaster ...
func (c cluster) StopMaster(clusterName string, masterRef string, duration time.Duration) error {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	_, err := service.StopMaster(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: masterRef}})
	return err
}

// StateMaster ...
func (c cluster) StateMaster(clusterName string, masterRef string, duration time.Duration) (*protocol.HostStatus, error) {
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

	service := protocol.NewClusterServiceClient(c.session.connection)
	return service.StateMaster(ctx, &protocol.ClusterNodeRequest{Name: clusterName, Host: &protocol.Reference{Name: masterRef}})
}

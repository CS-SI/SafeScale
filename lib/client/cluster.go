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
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/utils"
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
func (c *cluster) List(timeout time.Duration) (*protocol.ClusterListResponse, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}

	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	result, err := service.List(ctx, &googleprotobuf.Empty{})
	if err != nil {
		return nil, fail.ToError(err)
	}
	return result, nil
}

// Inspect ...
func (c *cluster) Inspect(clusterName string, timeout time.Duration) (*protocol.ClusterResponse, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
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
		return nil, fail.ToError(err)
	}
	return result, nil
}

// GetState gets cluster status
func (c *cluster) GetState(clusteName string, timeout time.Duration) (*protocol.ClusterStateResponse, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if clusteName == "" {
		return nil, fail.InvalidParameterError("clusteName", "cannot be empty string")
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

// // Reboots cluster
// func (c *cluster) Reboot(name string, timeout time.Duration) error {
// 	c.session.Connect()
// 	defer c.session.Disconnect()
// 	service := protocol.NewClusterServiceClient(c.session.connection)
// 	ctx, err := utils.GetContext(true)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = service.Reboot(ctx, &protocol.Reference{Name: name})
// 	return err
// }

// Start starts all the hosts of the cluster
func (c *cluster) Start(clusterName string, timeout time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}

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
func (c *cluster) Stop(clusterName string, timeout time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}

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
func (c *cluster) Create(def *protocol.ClusterCreateRequest, timeout time.Duration) (*protocol.ClusterResponse, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if def == nil {
		return nil, fail.InvalidParameterError("def", "cannot be nil")
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
func (c *cluster) Delete(clusterName string, timeout time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewHostServiceClient(c.session.connection)
	_, err := service.Delete(ctx, &protocol.Reference{Name: clusterName})
	return err
}

// Expand ...
func (c *cluster) Expand(req *protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if req == nil {
		return nil, fail.InvalidParameterError("req", "cannot be nil")
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
func (c *cluster) Shrink(req *protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if req == nil {
		return nil, fail.InvalidParameterError("req", "cannot be nil")
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
func (c *cluster) CheckFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
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
	_, err := service.Check(ctx, req)
	return err
}

// AddFeature ...
func (c *cluster) AddFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
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
	_, err := service.Add(ctx, req)
	return err
}

// RemoveFeature ...
func (c *cluster) RemoveFeature(clusterName, featureName string, params map[string]string, settings *protocol.FeatureSettings, duration time.Duration) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
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
func (c *cluster) ListInstalledFeatures(clusterName string, duration time.Duration) (*protocol.FeatureListResponse, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return nil, fail.InvalidParameterError("clusterName", "cannot be empty string")
	}

	c.session.Connect()
	defer c.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}
	_ = ctx
	//service := protocol.NewFeatureServiceClient(c.session.connection)
	return nil, fail.NotImplementedError()
}

// FindAvailableMaster ...
func (c *cluster) FindAvailableMaster(clusterName string, duration time.Duration) (*protocol.Host, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
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
	host, err := service.FindAvailableMaster(ctx, &protocol.Reference{Name:clusterName})
	if err != nil {
		return nil, fail.ToError(err)
	}
	return host, nil
}

// ListMasters ...
func (c *cluster) ListMasters(clusterName string, duration time.Duration) (*protocol.ClusterNodeListResponse, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
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
	list, err := service.ListMasters(ctx, &protocol.Reference{Name:clusterName})
	if err != nil {
		return nil, fail.ToError(err)
	}
	return list, nil
}

// ListNodes ...
func (c *cluster) ListNodes(clusterName string, duration time.Duration) (*protocol.ClusterNodeListResponse, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
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
	list, err := service.ListNodes(ctx, &protocol.Reference{Name:clusterName})
	if err != nil {
		return nil, fail.ToError(err)
	}
	return list, nil
}

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
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// var sshCfgCache = cache.NewMapCache()

// host is the safescale client part handling hosts
type cluster struct {
	// session is not used currently
	session *Session
}

// List ...
func (c *cluster) List(timeout time.Duration) (*protocol.ClusterListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.List(ctx, &googleprotobuf.Empty{})
}

// Inspect ...
func (c *cluster) Inspect(name string, timeout time.Duration) (*protocol.ClusterResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Inspect(ctx, &protocol.Reference{Name: name})

}

// GetState gets cluster status
func (c *cluster) GetState(name string, timeout time.Duration) (*protocol.ClusterStateResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.State(ctx, &protocol.Reference{Name: name})
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

// Start cluster
func (c *cluster) Start(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Start(ctx, &protocol.Reference{Name: name})
	return err
}

func (c *cluster) Stop(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Stop(ctx, &protocol.Reference{Name: name})
	return err
}

// Create ...
func (c *cluster) Create(def protocol.ClusterCreateRequest, timeout time.Duration) (*protocol.ClusterResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Create(ctx, &def)
}

// Delete deletes a cluster
func (c *cluster) Delete(name string, timeout time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewHostServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	_, err = service.Delete(ctx, &protocol.Reference{Name: name})
	return err
}

// Expand ...
func (c *cluster) Expand(def protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Expand(ctx, &def)
}

// Shrink ...
func (c *cluster) Shrink(def protocol.ClusterResizeRequest, duration time.Duration) (*protocol.ClusterNodeListResponse, error) {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewClusterServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return nil, err
	}

	return service.Shrink(ctx, &def)
}

// CheckFeature ...
func (c *cluster) CheckFeature(clusterName, featureName string, params map[string]string, settings protocol.FeatureSettings, duration time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewFeatureServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	req := protocol.FeatureActionRequest{
		Action:     protocol.FeatureAction_FA_CHECK,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   &settings,
	}
	_, err = service.Check(ctx, &req)
	return err
}

// AddFeature ...
func (c *cluster) AddFeature(clusterName, featureName string, params map[string]string, settings protocol.FeatureSettings, duration time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewFeatureServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	req := protocol.FeatureActionRequest{
		Action:     protocol.FeatureAction_FA_ADD,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   &settings,
	}
	_, err = service.Add(ctx, &req)
	return err
}

// RemoveFeature ...
func (c *cluster) RemoveFeature(clusterName, featureName string, params map[string]string, settings protocol.FeatureSettings, duration time.Duration) error {
	c.session.Connect()
	defer c.session.Disconnect()
	service := protocol.NewFeatureServiceClient(c.session.connection)
	ctx, err := utils.GetContext(true)
	if err != nil {
		return err
	}

	req := protocol.FeatureActionRequest{
		Action:     protocol.FeatureAction_FA_REMOVE,
		TargetType: protocol.FeatureTargetType_FT_CLUSTER,
		TargetRef:  &protocol.Reference{Name: clusterName},
		Variables:  params,
		Settings:   &settings,
	}
	_, err = service.Remove(ctx, &req)
	return err
}

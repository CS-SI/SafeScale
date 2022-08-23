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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package backend

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/config"
	"github.com/CS-SI/SafeScale/v22/lib/backend/listeners"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/heartbeat"
)

const (
	defaultHost string = "localhost" // By default, safescale daemon only listen on localhost
	defaultPort string = "50051"
)

// startBackend starts the gRPC server of SafeScale (the daemon)
func startBackend(cmd *cobra.Command) error {
	appwide.BuildFolderTree()
	suffix, err := config.Check(cmd)
	if err != nil {
		return fail.Wrap(err)
	}

	logrus.Infof("Starting daemon, listening on '%s', using metadata suffix '%s'", appwide.Config.Backend.Listen, suffix)
	lis, err := net.Listen("tcp", appwide.Config.Backend.Listen)
	if err != nil {
		return fail.Wrap(err, "failed to listen")
	}
	s := grpc.NewServer()

	logrus.Infoln("Registering gRPC services")
	protocol.RegisterBucketServiceServer(s, &listeners.BucketListener{})
	protocol.RegisterClusterServiceServer(s, &listeners.ClusterListener{})
	protocol.RegisterHostServiceServer(s, &listeners.HostListener{})
	protocol.RegisterFeatureServiceServer(s, &listeners.FeatureListener{})
	protocol.RegisterImageServiceServer(s, &listeners.ImageListener{})
	protocol.RegisterJobServiceServer(s, &listeners.JobManagerListener{})
	protocol.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	protocol.RegisterSubnetServiceServer(s, &listeners.SubnetListener{})
	protocol.RegisterSecurityGroupServiceServer(s, &listeners.SecurityGroupListener{})
	protocol.RegisterShareServiceServer(s, &listeners.ShareListener{})
	protocol.RegisterSshServiceServer(s, &listeners.SSHListener{})
	protocol.RegisterTemplateServiceServer(s, &listeners.TemplateListener{})
	protocol.RegisterTenantServiceServer(s, &listeners.TenantListener{})
	protocol.RegisterVolumeServiceServer(s, &listeners.VolumeListener{})
	protocol.RegisterLabelServiceServer(s, &listeners.LabelListener{})

	// enable heartbeat
	go heartbeat.RunHeartbeatService(":10102")

	// Register reflection service on gRPC server.
	reflection.Register(s)

	// Track goroutines
	startTrack()
	defer endTrack()

	// Expose runtime
	// - /debug/vars
	// - /debug/metrics
	// - /debug/fgprof
	common.ExposeRuntimeMetrics()

	operations.StartFeatureFileWatcher()

	fmt.Printf("safescale daemon version: %s\nReady to start backend on '%s' :-)\n", common.VersionString(), appwide.Config.Backend.Listen)
	err = s.Serve(lis)
	if err != nil {
		return fail.Wrap(err, "failed to start backend")
	}

	return nil
}

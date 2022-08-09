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
	"context"
	"fmt"
	"net"

	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/listeners"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/appwide/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/heartbeat"
	"github.com/hashicorp/go-version"
	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/fs"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"
)

const (
	defaultHost string = "localhost" // By default, safescale daemon only listen on localhost
	defaultPort string = "50051"
)

// startBackend starts the gRPC server of SafeScale (the daemon)
func startBackend(cmd *cobra.Command) error {
	listen, suffix, err := checkConfiguration(cmd)
	if err != nil {
		return fail.Wrap(err)
	}
	// appwide.BuildFolderTree()

	logrus.Infof("Starting daemon, listening on '%s', using metadata suffix '%s'", listen, suffix)
	lis, err := net.Listen("tcp", listen)
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

	fmt.Printf("safescale daemon version: %s\nReady to startBackend on '%s' :-)\n", common.VersionString(), listen)
	err = s.Serve(lis)
	if err != nil {
		return fail.Wrap(err, "failed to start backend")
	}

	return nil
}

// checkConfiguration makes sure configuration is ok
// log.Fatal is called if not to stop the program
func checkConfiguration(cmd *cobra.Command) (listen string, suffix string, ferr error) {
	logrus.Infoln("Checking configuration")
	_, xerr := iaas.GetTenantNames()
	if xerr != nil {
		return "", "", xerr
	}

	// DEV VAR
	suffix = ""
	// if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
	suffixCandidate, ok := env.Value("SAFESCALE_METADATA_SUFFIX")
	if ok && suffixCandidate != "" {
		suffix = suffixCandidate
	}

	safescaleEnv, err := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if err != nil {
		return "", "", fail.Wrap(err)
	}
	for _, v := range safescaleEnv {
		value, _ := env.Value(v)
		logrus.Infof("Using %s=%s ", v, value)
	}

	err = checkTerraform()
	if err != nil {
		return "", "", fail.Wrap(err)
	}

	return listen, suffix, nil
}

func checkTerraform() error {
	v1_2_6 := version.Must(version.NewVersion("1.2.6"))
	installer := hcinstall.NewInstaller()
	source := &fs.ExactVersion{
		Product: product.Terraform,
		Version: v1_2_6,
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil { //nolint
		// If binary not found, installs it
		release := &releases.ExactVersion{
			Product:    product.Terraform,
			Version:    v1_2_6,
			InstallDir: appwide.Config.Folders.ShareDir + "/terraform/bin",
		}
		logrus.Infof("installing terraform release %s", v1_2_6)
		execPath, err = installer.Install(context.Background(), []src.Installable{release})
		if err != nil {
			return err
		}
	}

	appwide.Config.Backend.Terraform.ExecPath = execPath
	// workingDir := settings.Folders.ShareDir+"/terraform/bin"
	// tf, err := tfexec.NewTerraform(workingDir, execPath)
	// if err != nil {
	// 	log.Fatalf("error running NewTerraform: %s", err)
	// }
	//
	// err = tf.Init(context.Background(), tfexec.Upgrade(true))
	// if err != nil {
	// 	log.Fatalf("error running Init: %s", err)
	// }
	//
	// state, err := tf.Show(context.Background())
	// if err != nil {
	// 	log.Fatalf("error running Show: %s", err)
	// }
	//
	// fmt.Println(state.FormatVersion) // "0.1"
	return nil
}

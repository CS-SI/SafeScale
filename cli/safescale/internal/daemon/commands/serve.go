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

package commands

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/hashicorp/go-version"
	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/fs"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"
	"github.com/hashicorp/terraform-exec/tfexec"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/listeners"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/app/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/heartbeat"
)

const (
	defaultHost string = "localhost" // By default, safescale daemon only listen on localhost
	defaultPort string = "50051"
)

// Serve starts the gRPC server of SafeScale (the daemon)
func Serve(c *cli.Context) {
	listen, suffix := checkConfiguration(c)

	logrus.Infof("Starting daemon, listening on '%s', using metadata suffix '%s'", listen, suffix)
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	logrus.Infoln("Registering services")
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

	fmt.Printf("safescale daemon version: %s\nReady to serve on '%s' :-)\n", common.VersionString(), listen)
	err = s.Serve(lis)
	if err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}

// checkConfiguration makes sure configuration is ok
// log.Fatal is called if not to stop the program
func checkConfiguration(c *cli.Context) (listen string, suffix string) {
	logrus.Infoln("Checking configuration")
	_, xerr := iaas.GetTenantNames()
	if xerr != nil {
		logrus.Fatalf(xerr.Error())
	}

	listen = common.AssembleListenString(c, defaultHost, defaultPort)

	// DEV VAR
	suffix = ""
	// if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
	suffixCandidate, ok := env.Value("SAFESCALE_METADATA_SUFFIX")
	if ok && suffixCandidate != "" {
		suffix = suffixCandidate
	}

	// envVars := os.Environ()
	// for _, envVar := range envVars {
	// 	if strings.HasPrefix(envVar, "SAFESCALE") {
	// 		logrus.Infof("Using %s", envVar)
	// 	}
	// }
	safescaleEnv, err := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if err != nil {
		logrus.Fatalf(err.Error())
	}
	for _, v := range safescaleEnv {
		logrus.Infof("Using %s", v)
	}

	err = checkTerraform(c)
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	return listen, suffix
}

func checkTerraform(c *cli.Context) error {
	// installer := &releases.ExactVersion{
	// 	Product: product.Terraform,
	// 	Version: version.Must(version.NewVersion("1.0.6")),
	// }
	// execPath, err := installer.Install(context.Background())
	// if err != nil {
	// 	log.Fatalf("error installing Terraform: %s", err)
	// }
	// execPath, err := installer.Install(context.Background())
	// if err != nil {
	// 	log.Fatalf("error installing Terraform: %s", err)
	// }

	v1_0_6 := version.Must(version.NewVersion("1.0.6"))
	installer := hcinstall.NewInstaller()
	source := &fs.ExactVersion{
		Product: product.Terraform,
		Version: v1_0_6,
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil { //nolint
		// If binary not found, installs it
		release := &releases.ExactVersion{
			Product: product.Terraform,
			Version: v1_0_6,
		}
		execPath, err = installer.Install(context.Background(), []src.Installable{release})
	}
	if err != nil {
		log.Fatalf(err.Error())
	}

	workingDir, err := determineTerraformWorkingDir(c)
	if err != nil {
		log.Fatalf(err.Error())
	}

	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		log.Fatalf("error running NewTerraform: %s", err)
	}

	err = tf.Init(context.Background(), tfexec.Upgrade(true))
	if err != nil {
		log.Fatalf("error running Init: %s", err)
	}

	state, err := tf.Show(context.Background())
	if err != nil {
		log.Fatalf("error running Show: %s", err)
	}

	fmt.Println(state.FormatVersion) // "0.1"
	return nil
}

func determineTerraformWorkingDir(c *cli.Context) (string, error) {
	// Default root dir
	dir := "/opt/safescale"
	from := "default"

	// Root dir from env
	if env.Lookup("SAFESCALE_ROOT_DIR") {
		dir, _ = env.Value("SAFESCALE_ROOT_DIR")
		from = "env"
	}

	// root dir from config file
	configFileFlag := c.String("conf")
	if configFileFlag != "" {
		confReader := viper.New()
		confReader.AddConfigPath(configFileFlag)
		rootDir := confReader.GetString("daemon.root_dir")
		if rootDir != "" {
			dir = rootDir
			from = "config file"
		}
	}

	// root dir from flags
	rootDirFlag := c.String("root-dir")
	if rootDirFlag != "" {
		dir = rootDirFlag
		from = "command flag"
	}

	if dir != "" {
		dir += "/bin"
		logrus.Debugf("Using root dir '%s' (from %s)", dir, from)
		return dir, nil
	}

	return "", fmt.Errorf("failed to determine safescale root dir")
}

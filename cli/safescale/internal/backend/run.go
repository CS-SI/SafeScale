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
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals"
	"github.com/CS-SI/SafeScale/v22/lib/backend/listeners"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/heartbeat"
)

const (
	defaultHost string = "localhost" // By default, safescale daemon only listen on localhost
	defaultPort string = "50051"
)

// startBackend starts the gRPC server of SafeScale (the daemon)
func startBackend(cmd *cobra.Command) error {
	global.BuildFolderTree()
	suffix, err := externals.Check(cmd)
	if err != nil {
		return fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// If terraform state has to be stored in consul, check consul is responding
	if global.Config.Backend.Terraform.StateInConsul {
		// If we use "internal" consul, starts consul
		if global.Config.Backend.Consul.Internal {
			xerr := externals.StartConsulServer(ctx)
			if xerr != nil {
				return xerr
			}
		}

		// check consul is working
	}

	logrus.Infof("Starting daemon, listening on '%s', using metadata suffix '%s'", global.Config.Backend.Listen, suffix)
	lis, err := net.Listen("tcp", global.Config.Backend.Listen)
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

	fmt.Printf("safescale backend version: %s\nReady to start backend on '%s' :-)\n", global.VersionString(), global.Config.Backend.Listen)
	err = s.Serve(lis)
	if err != nil {
		return fail.Wrap(err, "failed to start backend")
	}

	return nil
}

var consulLauncher sync.Once

func startConsulAgent(ctx context.Context) (ferr fail.Error) {
	ferr = nil
	consulLauncher.Do(func() {
		// creates configuration if not present
		consulRootDir := global.Config.Folders.ShareDir + "consul"
		consulEtcDir := consulRootDir + "/etc"
		// FIXME: decide what file name to use
		consulConfigFile := consulEtcDir + "/config.?"
		st, err := os.Stat(consulConfigFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				content := `
bootstrap = true
ui_config {
  enabled = true
}
data_dir = data
log_level = "INFO"
addresses {
  http = "0.0.0.0"
}
connect {
  enabled = false
}`
				file, err := os.Create(consulConfigFile)
				if err != nil {
					ferr = fail.Wrap(err, "failed to create consul configuration file")
					return
				}

				_, err = file.WriteString(content)
				if err != nil {
					ferr = fail.Wrap(err, "failed to write content of consul configuration file")
					return
				}

				err = file.Close()
				if err != nil {
					ferr = fail.Wrap(err, "failed to close consul configuration file")
					return
				}
			} else {
				ferr = fail.Wrap(err)
				return
			}
		} else if st.IsDir() {
			ferr = fail.NotAvailableError("'%s' is a directory; should be a file", consulConfigFile)
			return
		}

		// Starts consul agent
		args := []string{"agent", "-config-dir=etc", "-server", "-datacenter=safescale"}
		attr := &os.ProcAttr{
			Sys: &syscall.SysProcAttr{
				Chroot: global.Config.Folders.ShareDir + "consul",
			},
		}
		proc, err := os.StartProcess(global.Config.Backend.Consul.ExecPath, args, attr)
		if err != nil {
			ferr = fail.Wrap(err, "failed to start consul server")
			return
		}

		var doneCh chan any

		waitConsulExitFunc := func(process *os.Process) {
			ps, err := process.Wait()
			if err != nil {
				ferr = fail.Wrap(err)
				doneCh <- ferr
				return
			}

			ws, ok := ps.Sys().(syscall.WaitStatus)
			if ok {
				doneCh <- ws
				return
			}

			doneCh <- ps.Sys()
		}

		waitConsulExitFunc(proc)

		select {
		case <-ctx.Done():
			proc.Signal(os.Interrupt)
			return
		case val := <-doneCh:
			switch casted := val.(type) {
			case int:
				logrus.Debugf("consul ends with status '%d'", casted)
			case *os.ProcessState:
				ferr = fail.NewError("consul exit with an unhandled state of type '%s': %v", reflect.TypeOf(casted).String(), casted)
			default:
				ferr = fail.NewError("consul exit with an unexpected state of type '%s': %v", reflect.TypeOf(val).String(), val)
			}
			return
		}
	})

	return ferr
}

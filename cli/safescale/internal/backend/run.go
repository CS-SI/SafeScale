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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals"
	"github.com/CS-SI/SafeScale/v22/lib/backend/listeners"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/heartbeat"
	"github.com/CS-SI/SafeScale/v22/lib/utils/net/grpcweb"
	improbablegrpcweb "github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/mwitkow/go-conntrack"
	"github.com/mwitkow/go-conntrack/connhelpers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	defaultHost string = "localhost" // By default, safescale daemon only listen on localhost
	defaultPort string = "50051"
)

// startBackend starts the gRPC server of SafeScale (the daemon)
func startBackend(cmd *cobra.Command) error {
	err := global.BuildFolderTree()
	if err != nil {
		logrus.Fatal(err.Error())
		return err
	}

	suffix, err := externals.Check(cmd)
	if err != nil {
		return fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// If terraform state has to be stored in consul, check consul is responding
	if global.Settings.Backend.Terraform.StateInConsul {
		// If we use "internal" consul, starts consul
		if global.Settings.Backend.Consul.Internal {
			xerr := externals.StartConsulServer(ctx)
			if xerr != nil {
				return xerr
			}
		}

		// check consul is working
	}

	logrus.Infof("Starting backend, listening on '%s', using metadata suffix '%s'", global.Settings.Backend.Listen, suffix)

	// enable heartbeat
	go heartbeat.RunHeartbeatService(":10102")

	// Track goroutines
	startTrack()
	defer endTrack()

	operations.StartFeatureFileWatcher()

	// Starting everything
	errChan := make(chan error)
	serve(errChan)

	// Wait end of server
	err = <-errChan
	if err != nil {
		return fail.Wrap(err, "failed to start backend")
	}

	logrus.Infof("Terminated gracefully")
	return nil
}

func buildGRPCServer() *grpc.Server {
	logrus.Infoln("Registering gRPC services")
	grpcServer := grpc.NewServer()
	protocol.RegisterBucketServiceServer(grpcServer, &listeners.BucketListener{})
	protocol.RegisterClusterServiceServer(grpcServer, &listeners.ClusterListener{})
	protocol.RegisterHostServiceServer(grpcServer, &listeners.HostListener{})
	protocol.RegisterFeatureServiceServer(grpcServer, &listeners.FeatureListener{})
	protocol.RegisterImageServiceServer(grpcServer, &listeners.ImageListener{})
	protocol.RegisterJobServiceServer(grpcServer, &listeners.JobManagerListener{})
	protocol.RegisterNetworkServiceServer(grpcServer, &listeners.NetworkListener{})
	protocol.RegisterSubnetServiceServer(grpcServer, &listeners.SubnetListener{})
	protocol.RegisterSecurityGroupServiceServer(grpcServer, &listeners.SecurityGroupListener{})
	protocol.RegisterShareServiceServer(grpcServer, &listeners.ShareListener{})
	protocol.RegisterSshServiceServer(grpcServer, &listeners.SSHListener{})
	protocol.RegisterTemplateServiceServer(grpcServer, &listeners.TemplateListener{})
	protocol.RegisterTenantServiceServer(grpcServer, &listeners.TenantListener{})
	protocol.RegisterVolumeServiceServer(grpcServer, &listeners.VolumeListener{})
	protocol.RegisterLabelServiceServer(grpcServer, &listeners.LabelListener{})

	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)

	return grpcServer
}

var consulLauncher sync.Once

func startConsulAgent(ctx context.Context) (ferr fail.Error) {
	ferr = nil
	consulLauncher.Do(func() {
		// creates configuration if not present
		consulRootDir := global.Settings.Folders.ShareDir + "consul"
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
				Chroot: global.Settings.Folders.ShareDir + "consul",
			},
		}
		proc, err := os.StartProcess(global.Settings.Backend.Consul.ExecPath, args, attr)
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

func buildHttpRouter() (*http.ServeMux, fail.Error) {
	mux := http.NewServeMux()

	// frontendHandler, xerr := buildFrontendHttpHandler()
	// if xerr != nil {
	// 	return nil, xerr
	// }

	common.ExposeRuntimeMetrics(mux)
	addDebugHttpHandler(mux)
	// addGRPCHandler(mux, grpcServer, nil)
	return mux, nil
}

// buildServer configures the http server to use
func buildServer() *http.Server {
	grpcServer := buildGRPCServer()

	options := []improbablegrpcweb.Option{
		improbablegrpcweb.WithCorsForRegisteredEndpointsOnly(false),
	}

	// VPL: still need to figure out if I want to be able to limit origins...
	// allowedOrigins := makeAllowedOrigins(*flagAllowedOrigins)
	//	options = append(options, grpcweb.WithOriginFunc(makeHttpOriginFunc(common.Settings.Backend.AllowedOrigins)))

	// VPL: still need to figure out why I would want to use WebSockets...
	// if *useWebsockets {
	// 	logrus.Println("using websockets")
	// 	options = append(
	// 		options,
	// 		grpcweb.WithWebsockets(true),
	// 		grpcweb.WithWebsocketOriginFunc(makeWebsocketOriginFunc(allowedOrigins)),
	// 	)
	// 	if *websocketPingInterval >= time.Second {
	// 		logrus.Infof("websocket keepalive pinging enabled, the timeout interval is %s", websocketPingInterval.String())
	// 	}
	// 	if *websocketReadLimit > 0 {
	// 		options = append(options, grpcweb.WithWebsocketsMessageReadLimit(*websocketReadLimit))
	// 	}
	//
	// 	options = append(
	// 		options,
	// 		grpcweb.WithWebsocketPingInterval(*websocketPingInterval),
	// 	)
	//
	// 	var compressionMode websocket.CompressionMode
	// 	switch *websocketCompressionMode {
	// 	case "no_context_takeover":
	// 		compressionMode = websocket.CompressionNoContextTakeover
	// 	case "context_takeover":
	// 		compressionMode = websocket.CompressionContextTakeover
	// 	case "disabled":
	// 		compressionMode = websocket.CompressionDisabled
	// 	default:
	// 		logrus.Fatalf("unknown param for websocket compression mode: %s", *websocketCompressionMode)
	// 	}
	//
	// 	options = append(
	// 		options,
	// 		grpcweb.WithWebsocketCompressionMode(compressionMode),
	// 	)
	// }

	// if len(*flagAllowedHeaders) > 0 {
	// 	options = append(options, grpcweb.WithAllowedRequestHeaders(*flagAllowedHeaders))
	// }

	grpcwebWrapper, xerr := grpcweb.NewHandler(grpcServer, options...)
	if xerr != nil {
		logrus.Fatal(xerr.Error())
	}

	router, xerr := buildHttpRouter()
	if xerr != nil {
		logrus.Fatal(xerr.Error())
	}

	httpServer := &http.Server{
		Handler:      h2c.NewHandler(grpcwebWrapper.Handler(router), &http2.Server{}),
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}
	return httpServer
}

func serve(errChan chan error) error {
	defer fmt.Printf("safescale backend version: %s\nReady to serve on '%s' :-)\n", global.VersionString(), global.Settings.Backend.Listen)

	var (
		name     string
		listener net.Listener
		err      error
	)
	if global.Settings.Backend.UseTls {
		name = "http_tls"
		listener, err = buildListener(name)
		if err != nil {
			logrus.Fatal(err.Error())
		}

		tlsConf, err := buildServerTlsConfig()
		if err != nil {
			logrus.Fatal(err.Error())
		}

		listener = tls.NewListener(listener, tlsConf)
	} else {
		name = "http"
		listener, err = buildListener(name)
		if err != nil {
			logrus.Fatal(err.Error())
		}
	}

	go func() {
		logrus.Infof("listening for %s on %v", name, listener.Addr().String())

		server := buildServer()
		err := server.Serve(listener)
		if err != nil {
			errChan <- fmt.Errorf("%s server error: %v", name, err)
			return
		}

		errChan <- nil
	}()

	return nil
}

func buildListener(name string) (net.Listener, error) {
	listener, err := net.Listen("tcp", global.Settings.Backend.Listen)
	if err != nil {
		return nil, fail.Wrap(err, "failed listening on %s for '%s'", global.Settings.Backend.Listen, name)
	}

	out := conntrack.NewListener(listener,
		conntrack.TrackWithName(name),
		conntrack.TrackWithTcpKeepAlive(20*time.Second),
		conntrack.TrackWithTracing(),
	)
	return out, nil
}

func buildServerTlsConfig() (*tls.Config, error) {
	if global.Settings.Backend.Tls.CertFile == "" || global.Settings.Backend.Tls.KeyFile == "" {
		return nil, fail.InvalidRequestError("flags backend.tls.cert_file and backend.tls.key_file must be set")
	}

	tlsConfig, err := connhelpers.TlsConfigForServerCerts(global.Settings.Backend.Tls.CertFile, global.Settings.Backend.Tls.KeyFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed reading TLS server keys")
	}

	tlsConfig.MinVersion = tls.VersionTLS12
	if global.Settings.Backend.Tls.NoVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if len(global.Settings.Backend.Tls.CAs) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		if len(global.Settings.Backend.Tls.CAs) > 0 {
			for _, path := range global.Settings.Backend.Tls.CAs {
				data, err := ioutil.ReadFile(path)
				if err != nil {
					return nil, fail.Wrap(err, "failed reading CA file %v: %v", path)
				}

				ok := tlsConfig.RootCAs.AppendCertsFromPEM(data)
				if !ok {
					return nil, fail.NewError("failed processing CA file %v", path)
				}
			}
		} else {
			var err error
			tlsConfig.RootCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, fail.Wrap(err, "no CA files specified, fallback to system CA chain failed")
			}
		}
	}

	tlsConfig, err = connhelpers.TlsConfigWithHttp2Enabled(tlsConfig)
	if err != nil {
		return nil, fail.Wrap(err, "cannot configure http2 handling")
	}

	return tlsConfig, nil
}

func addDebugHttpHandler(mux *http.ServeMux) fail.Error {
	// Serving debugging helpers:
	mux.Handle("/metrics", promhttp.Handler())
	if global.Settings.Debug {
		mux.HandleFunc("/debug/http/requests", func(resp http.ResponseWriter, req *http.Request) {
			trace.Traces(resp, req)
		})
		mux.HandleFunc("/debug/http/events", func(resp http.ResponseWriter, req *http.Request) {
			trace.Events(resp, req)
		})
	}

	return nil
}

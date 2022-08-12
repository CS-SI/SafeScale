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

package webui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/appwide/env"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpclogrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/mwitkow/go-conntrack"
	"github.com/mwitkow/go-conntrack/connhelpers"
	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/web"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	// defaultHost string = "localhost"
	// defaultPort string = "50080"

	maxCallRecvMsgSize int = 4 * 1024 * 1024
)

// run starts the gRPC server of SafeScale (the daemon)
func run() error {
	// NOTE: is it the good behavior ? Shouldn't we fail ?
	// If trace settings cannot be registered, report it but do not fail
	// TODO: introduce use of configuration file with autoreload on change
	err := tracing.RegisterTraceSettings(traceSettings())
	if err != nil {
		return err
	}

	logrus.Infoln("Checking configuration")
	_, err = iaas.GetTenantNames()
	if err != nil {
		return err
	}

	safescaleEnv, err := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if err != nil {
		return err
	}
	for _, v := range safescaleEnv {
		value, _ := env.Value(v)
		logrus.Infof("Using %s=%s ", v, value)
	}

	backendConn, err := dialBackend()
	if err != nil {
		logrus.Fatal(err.Error())
	}

	grpcBackend := buildGrpcProxyServer(backendConn)
	errChan := make(chan error)

	options := []grpcweb.Option{
		grpcweb.WithCorsForRegisteredEndpointsOnly(false),
	}

	// VPL: still need to figure out if I want to be able to limit origins...
	// allowedOrigins := makeAllowedOrigins(*flagAllowedOrigins)
	//	options = append(options, grpcweb.WithOriginFunc(makeHttpOriginFunc(common.Config.WebUI.AllowedOrigins)))

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

	serveMux := http.NewServeMux()
	// Serving SafeScale Frontend:
	var fsHandler http.Handler
	if appwide.Config.WebUI.WebRoot != "" {
		st, err := os.Stat(appwide.Config.WebUI.WebRoot)
		if err != nil || !st.IsDir() {
			return fail.NotFoundError("failed to find webroot '%s'", appwide.Config.WebUI.WebRoot)
		}
		fsHandler = http.FileServer(http.Dir(appwide.Config.WebUI.WebRoot))
	} else {
		fsHandler = http.FileServer(http.FS(web.Webroot))
	}
	serveMux.Handle("/ui/", http.StripPrefix("/ui", fsHandler))

	// Serving debugging helpers:
	if appwide.Config.Debug {
		serveMux.Handle("/metrics", promhttp.Handler())
		serveMux.HandleFunc("/debug/requests", func(resp http.ResponseWriter, req *http.Request) {
			trace.Traces(resp, req)
		})
		serveMux.HandleFunc("/debug/events", func(resp http.ResponseWriter, req *http.Request) {
			trace.Events(resp, req)
		})
	}

	// Wrapped gRPC calls to backend:
	wrappedGrpc := grpcweb.WrapServer(grpcBackend, options...)
	serveMux.Handle("/", wrappedGrpc)

	// Starting everything
	server := buildFrontendServer(serveMux)
	switch appwide.Config.WebUI.UseTls {
	case false:
		listener, err := buildListener("http")
		if err != nil {
			return err
		}

		serveFrontend(server, listener, "http", errChan)

	case true:
		listener, err := buildListener("http_tls")
		if err != nil {
			return err
		}

		tlsConf, err := buildServerTls()
		if err != nil {
			logrus.Fatal(err.Error())
		}

		listener = tls.NewListener(listener, tlsConf)
		serveFrontend(server, listener, "http_tls", errChan)
	}

	fmt.Printf("safescale webui version: %s\nReady to run on '%s' :-)\n", common.VersionString(), appwide.Config.WebUI.Listen)
	return <-errChan
}

func buildGrpcProxyServer(backendConn *grpc.ClientConn) *grpc.Server {
	// gRPC-wide changes.
	grpc.EnableTracing = true
	logger := logrus.NewEntry(logrus.StandardLogger())
	grpclogrus.ReplaceGrpcLogger(logger)

	// gRPC proxy logic.
	director := func(ctx context.Context, fullMethodName string) (context.Context, *grpc.ClientConn, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		outCtx, _ := context.WithCancel(ctx)
		mdCopy := md.Copy()
		delete(mdCopy, "user-agent")
		// If this header is present in the request from the web client,
		// the actual connection to the backend will not be established.
		// https://github.com/improbable-eng/grpc-web/issues/568
		delete(mdCopy, "connection")
		outCtx = metadata.NewOutgoingContext(outCtx, mdCopy)
		return outCtx, backendConn, nil
	}

	// Server with logging and monitoring enabled.
	pgrpc := grpc.UnknownServiceHandler(proxy.TransparentHandler(director))
	out := grpc.NewServer(
		pgrpc,
		grpc.MaxRecvMsgSize(maxCallRecvMsgSize),
		grpcmiddleware.WithUnaryServerChain(
			grpclogrus.UnaryServerInterceptor(logger),
			grpc_prometheus.UnaryServerInterceptor,
		),
		grpcmiddleware.WithStreamServerChain(
			grpclogrus.StreamServerInterceptor(logger),
			grpc_prometheus.StreamServerInterceptor,
		),
	)
	return out
}

func buildFrontendServer(handler http.Handler) *http.Server {
	return &http.Server{
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Handler:      handler,
	}
}

func serveFrontend(server *http.Server, listener net.Listener, name string, errChan chan error) {
	go func() {
		logrus.Infof("listening for %s on: %v", name, listener.Addr().String())
		if err := server.Serve(listener); err != nil {
			errChan <- fmt.Errorf("%s server error: %v", name, err)
		}
	}()
}

func buildListener(name string) (net.Listener, error) {
	listener, err := net.Listen("tcp", appwide.Config.WebUI.Listen)
	if err != nil {
		return nil, fail.Wrap(err, "failed listening on %s for '%s'", appwide.Config.WebUI.Listen, name)
	}

	out := conntrack.NewListener(listener,
		conntrack.TrackWithName(name),
		conntrack.TrackWithTcpKeepAlive(20*time.Second),
		conntrack.TrackWithTracing(),
	)
	return out, nil
}

// dialBackend
func dialBackend() (*grpc.ClientConn, error) {
	var opt []grpc.DialOption
	// opt = append(opt, grpc.WithDefaultCallOptions(grpc.ForceCodec(newCodec())))

	if appwide.Config.Backend.DefaultAuthority != "" {
		opt = append(opt, grpc.WithAuthority(appwide.Config.Backend.DefaultAuthority))
	}

	if appwide.Config.Backend.UseTls {
		backendTls, err := buildBackendTls()
		if err != nil {
			return nil, err
		}
		opt = append(opt, grpc.WithTransportCredentials(credentials.NewTLS(backendTls)))
	} else {
		opt = append(opt, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opt = append(opt,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxCallRecvMsgSize)),
		// Deprecated: grpc.WithBackoffMaxDelay(common.Config.WebUI.BackendBackoffMaxDelay),
	)

	cc, err := grpc.Dial(appwide.Config.Backend.Listen, opt...)
	if err != nil {
		return nil, fail.InvalidRequestError("failed dialing backend: %v", err)
	}
	return cc, nil
}

func buildBackendTls() (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	tlsConfig.MinVersion = tls.VersionTLS12
	if appwide.Config.Backend.Tls.NoVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if len(appwide.Config.Backend.Tls.CAs) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, path := range appwide.Config.Backend.Tls.CAs {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return nil, fail.Wrap(err, "failed reading backend CA file %v: %v", path)
			}

			ok := tlsConfig.RootCAs.AppendCertsFromPEM(data)
			if !ok {
				return nil, fail.NewError("failed processing backend CA file %v", path)
			}
		}
	}

	if appwide.Config.WebUI.Tls.BackendClientCertFile != "" && appwide.Config.WebUI.Tls.BackendClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(appwide.Config.WebUI.Tls.BackendClientCertFile, appwide.Config.WebUI.Tls.BackendClientKeyFile)
		if err != nil {
			return nil, fail.Wrap(err, "failed reading TLS client keys: %v")
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	return tlsConfig, nil
}

func buildServerTls() (*tls.Config, error) {
	if appwide.Config.WebUI.Tls.CertFile == "" || appwide.Config.WebUI.Tls.KeyFile == "" {
		return nil, fail.InvalidRequestError("flags server_tls_cert_file and server_tls_key_file must be set")
	}

	tlsConfig, err := connhelpers.TlsConfigForServerCerts(appwide.Config.WebUI.Tls.CertFile, appwide.Config.WebUI.Tls.KeyFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed reading TLS server keys")
	}

	tlsConfig.MinVersion = tls.VersionTLS12
	switch appwide.Config.WebUI.Tls.CertVerification {
	case "none":
		tlsConfig.ClientAuth = tls.NoClientCert
	case "verify_if_given":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case "require":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fail.InvalidRequestError("unknown value '%v' for 'safescale.webui.tls.server.client_cert_verification", appwide.Config.WebUI.Tls.CertVerification)
	}
	if tlsConfig.ClientAuth != tls.NoClientCert {
		if len(appwide.Config.WebUI.Tls.CAs) > 0 {
			tlsConfig.ClientCAs = x509.NewCertPool()
			for _, path := range appwide.Config.WebUI.Tls.CAs {
				data, err := ioutil.ReadFile(path)
				if err != nil {
					return nil, fail.Wrap(err, "failed reading client CA file %v", path)
				}

				if ok := tlsConfig.ClientCAs.AppendCertsFromPEM(data); !ok {
					return nil, fail.NewError("failed processing client CA file %v", path)
				}
			}
		} else {
			var err error
			tlsConfig.ClientCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, fail.Wrap(err, "no client CA files specified, fallback to system CA chain failed")
			}
		}
	}
	tlsConfig, err = connhelpers.TlsConfigWithHttp2Enabled(tlsConfig)
	if err != nil {
		return nil, fail.Wrap(err, "cannot configure h2 handling")
	}

	return tlsConfig, nil
}

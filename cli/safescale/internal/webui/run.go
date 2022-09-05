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

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpclogrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/mwitkow/go-conntrack"
	"github.com/mwitkow/go-conntrack/connhelpers"
	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/CS-SI/SafeScale/v22/lib/frontend/web"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	// defaultHost string = "localhost"
	// defaultPort string = "50080"

	maxCallRecvMsgSize int = 4 * 1024 * 1024
)

// run starts the gRPC server of SafeScale (the daemon)
func run(cmd *cobra.Command) error {
	logrus.Infoln("Checking configuration")

	safescaleEnv, xerr := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if xerr != nil {
		return xerr
	}

	for _, v := range safescaleEnv {
		value, _ := env.Value(v)
		logrus.Infof("Using %s=%s ", v, value)
	}

	backendConn, xerr := dialBackend()
	if xerr != nil {
		logrus.Fatal(xerr.Error())
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

	mux, xerr := buildHttpRouter(grpcweb.WrapServer(grpcBackend, options...))
	if xerr != nil {
		return xerr
	}

	// Starting everything
	server := buildFrontendServer(mux)
	switch global.Config.WebUI.UseTls {
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

	fmt.Printf("safescale webui version: %s\nReady to run on '%s' :-)\n", global.VersionString(), global.Config.WebUI.Listen)
	return <-errChan
}

type grpcMux struct {
	*grpcweb.WrappedGrpcServer
}

func (m *grpcMux) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			m.ServeHTTP(w, r)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-User-Agent, X-Grpc-Web")
			w.Header().Set("grpc-status", "")
			w.Header().Set("grpc-message", "")
			if m.IsGrpcWebRequest(r) || m.IsAcceptableGrpcCorsRequest(r) {
				m.ServeHTTP(w, r)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func buildHttpRouter(grpcWrapper *grpcweb.WrappedGrpcServer) (*http.ServeMux, fail.Error) {
	mux := http.NewServeMux()

	frontendHandler, xerr := buildFrontendHttpHandler()
	if xerr != nil {
		return nil, xerr
	}

	xerr = buildDebugHttpHandler(mux)
	if xerr != nil {
		return nil, xerr
	}

	m := &grpcMux{grpcWrapper}
	mux.Handle("/", m.Handler(frontendHandler))

	return mux, nil
}

// buildFrontendHttpHandler Serving SafeScale Frontend
func buildFrontendHttpHandler() (http.Handler, fail.Error) {
	var fsHandler http.Handler
	if global.Config.WebUI.WebRoot != "" {
		st, err := os.Stat(global.Config.WebUI.WebRoot)
		if err != nil || !st.IsDir() {
			return nil, fail.NotFoundError("failed to find webroot '%s'", global.Config.WebUI.WebRoot)
		}

		fsHandler = http.FileServer(http.Dir(global.Config.WebUI.WebRoot))
	} else {
		fsHandler = http.FileServer(http.FS(web.Webroot))
	}

	return fsHandler, nil
}

func buildDebugHttpHandler(mux *http.ServeMux) fail.Error {
	// Serving debugging helpers:
	mux.Handle("/metrics", promhttp.Handler())
	if global.Config.Debug {
		mux.HandleFunc("/debug/requests", func(resp http.ResponseWriter, req *http.Request) {
			trace.Traces(resp, req)
		})
		mux.HandleFunc("/debug/events", func(resp http.ResponseWriter, req *http.Request) {
			trace.Events(resp, req)
		})
	}

	return nil
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
	out := grpc.NewServer(
		grpc.UnknownServiceHandler(proxy.TransparentHandler(director)),
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
		err := server.Serve(listener)
		if err != nil {
			errChan <- fmt.Errorf("%s server error: %v", name, err)
		}
	}()
}

func buildListener(name string) (net.Listener, error) {
	listener, err := net.Listen("tcp", global.Config.WebUI.Listen)
	if err != nil {
		return nil, fail.Wrap(err, "failed listening on %s for '%s'", global.Config.WebUI.Listen, name)
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

	if global.Config.Backend.DefaultAuthority != "" {
		opt = append(opt, grpc.WithAuthority(global.Config.Backend.DefaultAuthority))
	}

	if global.Config.Backend.UseTls {
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
	)

	cc, err := grpc.Dial(global.Config.Backend.Listen, opt...)
	if err != nil {
		return nil, fail.InvalidRequestError("failed dialing backend: %v", err)
	}
	return cc, nil
}

func buildBackendTls() (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	tlsConfig.MinVersion = tls.VersionTLS12
	if global.Config.Backend.Tls.NoVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if len(global.Config.Backend.Tls.CAs) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, path := range global.Config.Backend.Tls.CAs {
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

	if global.Config.WebUI.Tls.BackendClientCertFile != "" && global.Config.WebUI.Tls.BackendClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(global.Config.WebUI.Tls.BackendClientCertFile, global.Config.WebUI.Tls.BackendClientKeyFile)
		if err != nil {
			return nil, fail.Wrap(err, "failed reading TLS client keys: %v")
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	return tlsConfig, nil
}

func buildServerTls() (*tls.Config, error) {
	if global.Config.WebUI.Tls.CertFile == "" || global.Config.WebUI.Tls.KeyFile == "" {
		return nil, fail.InvalidRequestError("flags server_tls_cert_file and server_tls_key_file must be set")
	}

	tlsConfig, err := connhelpers.TlsConfigForServerCerts(global.Config.WebUI.Tls.CertFile, global.Config.WebUI.Tls.KeyFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed reading TLS server keys")
	}

	tlsConfig.MinVersion = tls.VersionTLS12
	switch global.Config.WebUI.Tls.CertVerification {
	case "none":
		tlsConfig.ClientAuth = tls.NoClientCert
	case "verify_if_given":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case "require":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fail.InvalidRequestError("unknown value '%v' for 'safescale.webui.tls.server.client_cert_verification", global.Config.WebUI.Tls.CertVerification)
	}
	if tlsConfig.ClientAuth != tls.NoClientCert {
		if len(global.Config.WebUI.Tls.CAs) > 0 {
			tlsConfig.ClientCAs = x509.NewCertPool()
			for _, path := range global.Config.WebUI.Tls.CAs {
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

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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/web"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/mwitkow/go-conntrack/connhelpers"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// startWebUI starts the gRPC server of SafeScale (the daemon)
func startWebUI(_ *cobra.Command) error {
	logrus.Infoln("Checking configuration")

	// safescaleEnv, xerr := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// for _, v := range safescaleEnv {
	// 	value, _ := env.Value(v)
	// 	logrus.Infof("Using %s=%s ", v, value)
	// }

	// Starting everything
	errChan := make(chan error)
	serve(errChan)
	fmt.Printf("safescale webui version: %s\nReady to startWebUI on '%s' :-)\n", global.VersionString(), global.Settings.WebUI.Listen)

	// Wait end of server
	err := <-errChan
	if err != nil {
		return fail.Wrap(err, "failed to start webui")
	}

	logrus.Infof("Terminated gracefully")

	return nil
}

// serve starts the server to handle the Web UI
func serve(errChan chan error) {
	var (
		name     string
		listener net.Listener
		err      error
	)
	if global.Settings.WebUI.UseTls {
		name = "http_tls"
		listener, err = common.BuildListener(name, global.Settings.WebUI.Listen)
		if err != nil {
			logrus.Fatal(err.Error())
		}

		tlsConf, err := buildServerTlsConfig(global.Settings.WebUI.Tls.CertFile, global.Settings.WebUI.Tls.KeyFile)
		if err != nil {
			logrus.Fatal(err.Error())
		}

		listener = tls.NewListener(listener, tlsConf)
	} else {
		name = "http"
		listener, err = common.BuildListener(name, global.Settings.WebUI.Listen)
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
}

// buildServerTlsConfig creates the needed *tls.Config based on App settings
func buildServerTlsConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("certFile | keyFile")
	}

	tlsConfig, err := connhelpers.TlsConfigForServerCerts(certFile, keyFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed reading TLS server keys")
	}

	tlsConfig.MinVersion = tls.VersionTLS12
	switch global.Settings.WebUI.Tls.CertVerification {
	case "none":
		tlsConfig.ClientAuth = tls.NoClientCert
	case "verify_if_given":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case "require":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fail.InvalidRequestError("unknown value '%v' for 'safescale.webui.tls.server.client_cert_verification", global.Settings.WebUI.Tls.CertVerification)
	}
	if tlsConfig.ClientAuth != tls.NoClientCert {
		if len(global.Settings.WebUI.Tls.CAs) > 0 {
			tlsConfig.ClientCAs = x509.NewCertPool()
			for _, path := range global.Settings.WebUI.Tls.CAs {
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

// buildServer creates the *http.Server needed to handle requests
func buildServer() *http.Server {
	router, xerr := buildHttpRouter()
	if xerr != nil {
		logrus.Fatal(xerr.Error())
	}

	return &http.Server{
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Handler:      router,
	}
}

// buildHttpRouter builds the router of requests
func buildHttpRouter() (*http.ServeMux, fail.Error) {
	mux, xerr := common.BuildHttpRouter()
	if xerr != nil {
		return nil, xerr
	}

	frontendHandler, xerr := buildFrontendHttpHandler()
	if xerr != nil {
		return nil, xerr
	}

	mux.Handle("/", frontendHandler)
	return mux, nil
}

// buildFrontendHttpHandler Serving SafeScale Frontend
func buildFrontendHttpHandler() (http.Handler, fail.Error) {
	var fsHandler http.Handler
	if global.Settings.WebUI.WebRoot != "" {
		st, err := os.Stat(global.Settings.WebUI.WebRoot)
		if err != nil || !st.IsDir() {
			return nil, fail.NotFoundError("failed to find webroot '%s'", global.Settings.WebUI.WebRoot)
		}

		fsHandler = http.FileServer(http.Dir(global.Settings.WebUI.WebRoot))
	} else {
		fsHandler = http.FileServer(http.FS(web.Webroot))
	}

	return fsHandler, nil
}

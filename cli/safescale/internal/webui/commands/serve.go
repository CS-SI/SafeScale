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
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
)

const (
	defaultHost string = "localhost"
	defaultPort string = "50080"
)

// serve starts the gRPC server of SafeScale (the daemon)
func serve(c *cli.Context) {
	// NOTE: is it the good behavior ? Shouldn't we fail ?
	// If trace settings cannot be registered, report it but do not fail
	// TODO: introduce use of configuration file with autoreload on change
	err := tracing.RegisterTraceSettings(webuiTrace())
	if err != nil {
		logrus.Errorf(err.Error())
	}

	logrus.Infoln("Checking configuration")
	_, err = iaas.GetTenantNames()
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	listen := common.AssembleListenString(c, defaultHost, defaultPort)

	// DEV VAR
	suffix := ""
	if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
		suffix = suffixCandidate
	}

	envVars := os.Environ()
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "SAFESCALE") {
			logrus.Infof("Using %s", envVar)
		}
	}

	logrus.Infof("Starting daemon, listening on '%s', using metadata suffix '%s'", listen, suffix)
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	_, _ = lis, s // temporary for successful compilation
	// Expose runtime
	// - /debug/vars
	// - /debug/metrics
	// - /debug/fgprof
	common.ExposeRuntimeMetrics()

	fmt.Printf("safescale webui version: %s\nReady to serve on '%s' :-)\n", common.VersionString(), listen)
	//if err := s.Serve(lis); err != nil {
	logrus.Fatalf("Failed to serve: %v", err)
	//}
}

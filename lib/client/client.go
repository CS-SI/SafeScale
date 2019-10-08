/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"os"
	"strconv"
	"strings"

	logr "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Session units the different resources proposed by safescaled as safescale client
type Session struct {
	Bucket     *bucket
	Data       *data
	Host       *host
	Image      *image
	JobManager *jobManager
	Network    *network
	Share      *share
	SSH        *ssh
	Template   *template
	Tenant     *tenant
	Volume     *volume

	safescaledHost string
	safescaledPort int
	connection     *grpc.ClientConn

	tenantName string
}

// Client is a instance of Session used temporarily until the session logic in safescaled is implemented
type Client *Session

// DefaultTimeout tells to use the timeout by default depending on context
var (
	DefaultConnectionTimeout = temporal.GetConnectSSHTimeout()
	DefaultExecutionTimeout  = temporal.GetExecutionTimeout()
)

// New returns an instance of safescale Client
func New() Client {
	safescaledPort := 50051

	if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
		num, err := strconv.Atoi(portCandidate)
		if err == nil {
			safescaledPort = num
		}
	}

	s := &Session{
		safescaledHost: "localhost",
		safescaledPort: safescaledPort,
	}

	s.Bucket = &bucket{session: s}
	s.Data = &data{session: s}
	s.Host = &host{session: s}
	s.Image = &image{session: s}
	s.Network = &network{session: s}
	s.JobManager = &jobManager{session: s}
	s.Share = &share{session: s}
	s.SSH = &ssh{session: s}
	s.Template = &template{session: s}
	s.Tenant = &tenant{session: s}
	s.Volume = &volume{session: s}
	return s
}

// Connect establishes connection with safescaled
func (s *Session) Connect() {
	if s.connection == nil {
		s.connection = utils.GetConnection(s.safescaledHost, s.safescaledPort)
	}
}

// Disconnect cuts the connection with safescaled
func (s *Session) Disconnect() {
	if s.connection != nil {
		err := s.connection.Close()
		if err != nil {
			logr.Error(err)
		}
		s.connection = nil
	}
}

// DecorateError changes the error to something more comprehensible
func DecorateError(err error, action string, maySucceed bool) error {
	if IsTimeoutError(err) {
		msg := "%s took too long (> %v) to respond"
		if maySucceed {
			msg += " (may eventually succeed)"
		}
		return fmt.Errorf(msg, action, DefaultExecutionTimeout)
	}

	// msg := err.Error()
	// if strings.Contains(msg, "desc = ") {
	// 	pos := strings.Index(msg, "desc = ") + 7
	// 	msg = msg[pos:]

	// 	if strings.Index(msg, " :") == 0 {
	// 		msg = msg[2:]
	// 	}
	// 	return fmt.Errorf(msg)
	// }
	return err
}

// IsTimeoutError tells if the err is a timeout kind
func IsTimeoutError(err error) bool {
	// FIXME Look at that
	/*
		if _, ok := err.(common.ErrTimeout); ok {
			return true
		}
	*/

	return status.Code(err) == codes.DeadlineExceeded
}

// IsProvisioningError detects provisioning errors
func IsProvisioningError(err error) bool {
	errText := err.Error()
	return strings.Contains(errText, "PROVISIONING_ERROR:")
}

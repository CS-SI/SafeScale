/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
	"time"

	"github.com/pkg/errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/broker/utils"
)

// Session units the different resources proposed by brokerd as broker client
type Session struct {
	Bucket   *bucket
	Host     *host
	Share    *share
	Network  *network
	Ssh      *ssh
	Tenant   *tenant
	Volume   *volume
	Template *template
	Image    *image

	brokerdHost string
	brokerdPort int
	connection  *grpc.ClientConn

	tenantName string
}

// Client is a instance of Session used temporarily until the session logic in brokerd is implemented
type Client *Session

// DefaultTimeout tells to use the timeout by default depending on context
const (
	DefaultConnectionTimeout = 30 * time.Second
	DefaultExecutionTimeout  = 5 * time.Minute
)

// New returns an instance of broker Client
func New() Client {
	s := &Session{
		brokerdHost: "localhost",
		brokerdPort: 50051,
	}

	s.Bucket = &bucket{session: s}
	s.Host = &host{session: s}
	s.Share = &share{session: s}
	s.Network = &network{session: s}
	s.Ssh = &ssh{session: s}
	s.Tenant = &tenant{session: s}
	s.Volume = &volume{session: s}
	s.Template = &template{session: s}
	s.Image = &image{session: s}
	return s
}

// Connect establishes connection with brokerd
func (s *Session) Connect() {
	if s.connection == nil {
		s.connection = utils.GetConnection(s.brokerdHost, s.brokerdPort)
	}
}

// Disconnect cuts the connection with brokerd
func (s *Session) Disconnect() {
	if s.connection != nil {
		s.connection.Close()
		s.connection = nil
	}
}

// DecorateError changes the error to something more comprehensible when
// timeout occured
func DecorateError(err error, action string, maySucceed bool) error {
	if IsTimeout(err) {
		msg := "%s took too long (> %v) to respond"
		if maySucceed {
			msg += " (may eventually succeed)"
		}
		return fmt.Errorf(msg, action, DefaultExecutionTimeout)
	}
	msg := err.Error()
	if strings.Index(msg, "desc = ") != -1 {
		pos := strings.Index(msg, "desc = ") + 7
		msg = msg[pos:]

		if strings.Index(msg, " :") == 0 {
			msg = msg[2:]
		}
		return errors.New(msg)
	}
	return err
}

// IsTimeout tells if the err is a timeout kind
func IsTimeout(err error) bool {
	return status.Code(err) == codes.DeadlineExceeded
}

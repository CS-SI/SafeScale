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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Session units the different resources proposed by brokerd as broker client
type Session struct {
	Container *container
	Host      *host
	Nas       *nas
	Network   *network
	Ssh       *ssh
	Tenant    *tenant
	Volume    *volume
	Template  *template
	Image     *image

	// For future use...
	brokerdAddress string
	brokerdPort    uint16
	tenantName     string
}

// Client is a instance of Session used temporarily until the session logic in brokerd is implemented
type Client *Session

// DefaultTimeout tells to use the timeout by default depending on context
const (
	DefaultConnectionTimeout = 10 * time.Second
	DefaultExecutionTimeout  = 5 * time.Minute
)

// New returns an instance of broker Client
func New() Client {
	s := &Session{}
	s.Container = &container{session: s}
	s.Host = &host{session: s}
	s.Nas = &nas{session: s}
	s.Network = &network{session: s}
	s.Ssh = &ssh{session: s}
	s.Tenant = &tenant{session: s}
	s.Volume = &volume{session: s}
	s.Template = &template{session: s}
	s.Image = &image{session: s}
	return s
}

// DecorateError changes the error to something more comprehensible when
// timeout occured
func DecorateError(err error, action string, maySucceed bool) error {
	if status.Code(err) == codes.DeadlineExceeded {
		msg := "%s took too long (> %v) to respond"
		if maySucceed {
			msg += " (may eventually succeed)"
		}
		return fmt.Errorf(msg, action, DefaultExecutionTimeout)
	}
	return err
}

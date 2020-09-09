/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

    "github.com/sirupsen/logrus"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    "github.com/CS-SI/SafeScale/lib/server/utils"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Session units the different resources proposed by safescaled as safescale client
type Session struct {
    Bucket        bucket
    Cluster       cluster
    Host          host
    Image         image
    JobManager    jobManager
    Network       network
    SecurityGroup securityGroup
    Share         share
    SSH           ssh
    Template      template
    Tenant        tenant
    Volume        volume

    server     string
    connection *grpc.ClientConn

    tenantName string

    task concurrency.Task
}

// DefaultTimeout tells to use the timeout by default depending on context
var (
    DefaultConnectionTimeout = temporal.GetConnectSSHTimeout()
    DefaultExecutionTimeout  = temporal.GetExecutionTimeout()
)

const (
    defaultServerHost string = "localhost"
    defaultServerPort string = "50051"
)

// New returns an instance of safescale Client
func New(server string) (_ *Session, xerr fail.Error) {
    // Validate server parameter (can be empty string...)
    if server != "" {
        if server, xerr = validateServerString(server); xerr != nil {
            return nil, fail.Wrap(xerr, "server is invalid")
        }
    }
    // if server is empty, try to see if env SAFESCALED_SERVER is set...
    if server == "" {
        server = os.Getenv("SAFESCALED_SERVER")
        if server, xerr = validateServerString(server); xerr != nil {
            logrus.Warnf("Content of environment variable SAFESCALED_SERVER is invalid, ignoring.")
            server = ""
        }
    }
    // LEGACY: if server is empty, host will be localhost, try to see if env SAFESCALED_PORT is set
    if server == "" {
        if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
            num, err := strconv.Atoi(portCandidate)
            if err != nil || num <= 0 {
                logrus.Warnf("Content of environment variable SAFESCALED_PORT is invalid, must be an int")
            } else {
                server = defaultServerHost + ":" + portCandidate
            }
        }
    }
    if server == "" {
        // empty string, so default value to server
        server = defaultServerHost + ":" + defaultServerPort
    }

    s := &Session{server: server}
    s.task, xerr = concurrency.VoidTask()
    if xerr != nil {
        return nil, xerr
    }

    s.Bucket = bucket{session: s}
    s.Cluster = cluster{session: s}
    s.Host = host{session: s}
    s.Image = image{session: s}
    s.Network = network{session: s}
    s.JobManager = jobManager{session: s}
    s.Share = share{session: s}
    s.SSH = ssh{session: s}
    s.Template = template{session: s}
    s.Tenant = tenant{session: s}
    s.Volume = volume{session: s}

    return s, nil
}

func validateServerString(server string) (string, fail.Error) {
    if server == "" {
        return "", nil
    }

    parts := strings.Split(server, ":")
    switch len(parts) {
    case 1:
        server = parts[0] + ":" + defaultServerPort
    case 2:
        num, err := strconv.Atoi(parts[1])
        if err != nil || num <= 0 {
            return "", fail.InvalidParameterError("server", "is invalid")
        }
        if parts[0] == "" {
            server = defaultServerHost
        } else {
            server = parts[0]
        }
        server += ":" + parts[1]
    default:
        return "", fail.InvalidParameterError("server", "is invalid")
    }
    return server, nil
}

// Connect establishes connection with safescaled
func (s *Session) Connect() {
    if s.connection == nil {
        s.connection = utils.GetConnection(s.server)
    }
}

// Disconnect cuts the connection with safescaled
func (s *Session) Disconnect() {
    if s.connection != nil {
        err := s.connection.Close()
        if err != nil {
            logrus.Error(err)
        }
        s.connection = nil
    }
}

// SetTask set the task the session must use
func (s *Session) SetTask(task concurrency.Task) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }
    s.task = task
    return nil
}

// GetTask ...
func (s *Session) GetTask() (concurrency.Task, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if s.task.IsNull() {
        return nil, fail.InvalidInstanceContentError("s.task", "cannot be nil")
    }
    return s.task, nil
}

// DecorateTimeoutError changes the error to something more comprehensible when
// timeout occurred
func DecorateTimeoutError(err error, action string, maySucceed bool) error {
    if isTimeoutError(err) {
        msg := "%s took too long (> %v) to respond"
        if maySucceed {
            msg += " (may eventually succeed)"
        }
        return fmt.Errorf(msg, action, DefaultExecutionTimeout)
    }
    msg := err.Error()
    if strings.Contains(msg, "desc = ") {
        pos := strings.Index(msg, "desc = ") + 7
        msg = msg[pos:]

        if strings.Index(msg, " :") == 0 {
            msg = msg[2:]
        }
        return fmt.Errorf(msg)
    }
    return err
}

// isTimeoutError tells if the err is a timeout kind
func isTimeoutError(err error) bool {
    return status.Code(err) == codes.DeadlineExceeded
}

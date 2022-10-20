/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package bylib

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	ssh2 "github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/sshtunnel"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/pkg/sftp"
)

// Profile helper to manage ssh session
type Profile struct {
	Hostname               string        `json:"hostname"`
	IPAddress              string        `json:"ip_address"`
	Port                   int           `json:"port"`
	User                   string        `json:"user"`
	PrivateKey             string        `json:"private_key"`
	LocalPort              int           `json:"-"`
	LocalHost              string        `json:"local_host"`
	GatewayConfig          sshapi.Config `json:"primary_gateway_config,omitempty"`
	SecondaryGatewayConfig sshapi.Config `json:"secondary_gateway_config,omitempty"`
}

func (sconf *Profile) CreatePersistentTunneling() fail.Error {
	return nil
}

func NewProfile(hostname string, ipAddress string, port int, user string, privateKey string, localPort int, localHost string, gatewayConfig *Profile, secondaryGatewayConfig *Profile) *Profile {
	return &Profile{Hostname: hostname, IPAddress: ipAddress, Port: port, User: user, PrivateKey: privateKey, LocalPort: localPort, LocalHost: localHost, GatewayConfig: gatewayConfig, SecondaryGatewayConfig: secondaryGatewayConfig}
}

func NewConnector(ac sshapi.Config) (*Profile, fail.Error) {
	if valid.IsNil(ac) {
		return nil, fail.InvalidParameterCannotBeNilError("ac")
	}

	hostname, _ := ac.GetHostname()
	IPAddress, _ := ac.GetIPAddress()
	port, _ := ac.GetPort()
	user, _ := ac.GetUser()
	privateKey, _ := ac.GetPrivateKey()
	localPort, _ := ac.GetLocalPort()
	localHost, _ := ac.GetLocalHost()
	gatewayConfig, _ := ac.GetPrimaryGatewayConfig()
	secondaryGatewayConfig, _ := ac.GetSecondaryGatewayConfig()

	return &Profile{Hostname: hostname, IPAddress: IPAddress, Port: int(port), User: user, PrivateKey: privateKey, LocalPort: int(localPort), LocalHost: localHost, GatewayConfig: gatewayConfig, SecondaryGatewayConfig: secondaryGatewayConfig}, nil
}

// Tunnel a SSH tunnel
type Tunnel struct {
	cfg  Profile // nolint
	port int     // nolint
}

func (sconf *Profile) Config() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf, nil
}

func (sconf *Profile) GetUser() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.User, nil
}

func (sconf *Profile) GetHostname() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.Hostname, nil
}

func (sconf *Profile) GetLocalHost() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.LocalHost, nil
}

func (sconf *Profile) GetPort() (uint, fail.Error) {
	if valid.IsNil(sconf) {
		return 0, fail.InvalidInstanceError()
	}
	return uint(sconf.Port), nil
}

func (sconf *Profile) GetLocalPort() (uint, fail.Error) {
	if valid.IsNil(sconf) {
		return 0, fail.InvalidInstanceError()
	}
	return uint(sconf.LocalPort), nil
}

func (sconf *Profile) GetIPAddress() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.IPAddress, nil
}

func (sconf *Profile) GetPrivateKey() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.PrivateKey, nil
}

func (sconf *Profile) GetPrimaryGatewayConfig() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.GatewayConfig, nil
}

func (sconf *Profile) GetSecondaryGatewayConfig() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.SecondaryGatewayConfig, nil
}

func (sconf *Profile) GetGatewayConfig(num uint) (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}

	switch num {
	case 0:
		return sconf.GatewayConfig, nil
	case 1:
		return sconf.SecondaryGatewayConfig, nil
	default:
		return nil, fail.InvalidParameterError("num", "only can be 0 or 1")
	}
}

func (sconf *Profile) HasGateways() (bool, fail.Error) {
	if valid.IsNil(sconf) {
		return false, fail.InvalidInstanceError()
	}

	if sconf.GatewayConfig == nil && sconf.SecondaryGatewayConfig == nil {
		return false, nil
	}

	return true, nil
}

// LibCommand defines an SSH command
type LibCommand struct {
	withSudo bool
	username string
	cfg      *Profile
	cmd      *exec.Cmd
	tunnels  *sshtunnel.SSHTunnel
}

func (sc *LibCommand) closeTunneling() error {
	if sc.tunnels != nil {
		sc.tunnels.Close()
	}

	return nil
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (sc *LibCommand) Output() (_ []byte, ferr error) {
	if sc.cmd.Stdout != nil {
		return []byte(""), nil
	}

	defer func() {
		nerr := sc.cleanup()
		if nerr != nil {
			ferr = nerr
		}
	}()

	content, err := sc.cmd.Output()
	if err != nil {
		return nil, err
	}

	return content, nil
}

// Display ...
func (sc *LibCommand) Display() string {
	return strings.Join(sc.cmd.Args, " ")
}

func (sc *LibCommand) String() string {
	return sc.Display()
}

// RunWithTimeout ...
func (sc *LibCommand) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	var rc int
	var rout string
	var rerr string
	var pb fail.Error

	expandedTimeout := timeout
	if expandedTimeout > 0 {
		expandedTimeout += 5 * time.Second
	}

	xerr := retry.WhileUnsuccessful(func() error { // retry only if we have a tunnel problem
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return retry.StopRetryError(ctx.Err())
		}

		tu, _, err := sc.cfg.CreateTunneling(ctx)
		if err != nil {
			return fail.NewError("failure creating tunnel: %w", err)
		}
		sc.tunnels = tu
		defer tu.Close()

		rv, out, sterr, xerr := sc.NewRunWithTimeout(ctx, outs, timeout)
		if rv == -2 {
			return fmt.Errorf("tunnel problem")
		}
		rc = rv
		rout = out
		rerr = sterr
		pb = xerr
		return nil
	},
		0,               // internal select takes care of it
		expandedTimeout) // no need to increase this, if there is a tunnel problem, it happens really fast

	if xerr != nil {
		return -1, "", "", xerr
	}

	return rc, rout, rerr, pb
}

// PublicKeyFromStr ...
func PublicKeyFromStr(keyStr string) ssh.AuthMethod {
	key, err := ssh.ParsePrivateKey([]byte(keyStr))
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

// NewRunWithTimeout ...
func (sc *LibCommand) NewRunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("command=%s", sc.Display())
	defer tracer.Exiting()

	type result struct {
		errorcode int
		stdout    string
		stderr    string
		reserr    error
	}

	results := make(chan result)
	enough := time.After(timeout)

	go func() {
		defer close(results)

		directConfig := &ssh.ClientConfig{
			User: sc.cfg.User,
			Auth: []ssh.AuthMethod{
				PublicKeyFromStr(sc.cfg.PrivateKey),
			},
			HostKeyCallback: sshtunnel.TrustedHostKeyCallback(""),
			Timeout:         10 * time.Second,
		}

		logrus.WithContext(ctx).Tracef("Dialing to %s:%d using %s:%d", sc.cfg.LocalHost, sc.cfg.LocalPort, "localhost", sc.tunnels.GetLocalEndpoint().Port())
		client, err := sshtunnel.DialSSHWithTimeout("tcp", fmt.Sprintf("%s:%d", sc.cfg.LocalHost, sc.tunnels.GetLocalEndpoint().Port()), directConfig, 45*time.Second)
		if err != nil {
			if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
				logrus.WithContext(ctx).Tracef(spew.Sdump(err))
			}
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					results <- result{
						errorcode: 255,
						stdout:    "",
						stderr:    "",
						reserr:    err,
					}
					return
				}
			}

			results <- result{
				errorcode: 255,
				stdout:    "",
				stderr:    "",
				reserr:    err,
			}
			return
		}
		defer func() {
			if client != nil {
				clErr := client.Close()
				if clErr != nil {
					logrus.Warn(clErr)
				}
			}
		}()

		beginDial := time.Now()
		retries := 0
		eofCount := 0

		var session *ssh.Session

		err = retry.WhileUnsuccessful(func() error { // FIXME: Turn this into goroutine
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			// Each ClientConn can support multiple interactive sessions, represented by a Session.
			var internalErr error
			var newsession *ssh.Session
			newsession, internalErr = client.NewSession()
			if internalErr != nil {
				retries = retries + 1 // nolint
				logrus.WithContext(ctx).Tracef("problem creating session: %s", internalErr.Error())
				if strings.Contains(internalErr.Error(), "EOF") {
					eofCount++
					if eofCount >= 14 {
						return retry.StopRetryError(internalErr, "client seems dead")
					}
				}
				if strings.Contains(internalErr.Error(), "unexpected packet") {
					return retry.StopRetryError(internalErr, "client seems dead")
				}
				return internalErr
			}
			if session != nil { // race condition mitigation
				return fmt.Errorf("too late")
			}
			logrus.WithContext(ctx).Tracef("creating the session took %s and %d retries", time.Since(beginDial), retries)
			session = newsession
			return nil
		}, 2*time.Second, 150*time.Second)
		if err != nil {
			if strings.Contains(err.Error(), "seems dead") {
				results <- result{
					errorcode: -2,
					stdout:    "",
					stderr:    "",
					reserr:    err,
				}
			} else {
				results <- result{
					errorcode: -1,
					stdout:    "",
					stderr:    "",
					reserr:    err,
				}
			}
			return
		}
		defer func() {
			if session != nil {
				err = session.Close()
				if err != nil {
					if !strings.Contains(err.Error(), "EOF") {
						logrus.Warnf("error closing session: %v", err)
					}
				}
			}
		}()

		if sc.cmd == nil {
			results <- result{-1, "", "", fail.AbortedError(nil, "nil ssh command!!")}
			return
		}

		if len(sc.cmd.String()) == 0 {
			results <- result{-1, "", "", fail.AbortedError(nil, "empty ssh command!!")}
			return
		}

		// Once a Session is created, you can execute a single command on
		// the remote side using the Run method.
		var errorCode int

		var be bytes.Buffer
		var b bytes.Buffer
		session.Stdout = &b
		session.Stderr = &be

		opTimeout := timeout
		if timeout != 0 {
			if 150*time.Second > timeout {
				opTimeout = 150 * time.Second
			}
		}

		breaker := false
		for {
			if breaker {
				break
			}

			beginIter := time.Now()
			if err := sshtunnel.RunCommandInSSHSessionWithTimeout(session, sc.cmd.String(), opTimeout); err != nil {
				logrus.WithContext(ctx).Debugf("Error running command after %s: %s", time.Since(beginIter), err.Error())
				errorCode = -1

				if ee, ok := err.(*ssh.ExitError); ok {
					errorCode = ee.ExitStatus()
					logrus.WithContext(ctx).Debugf("Found an exit error of command '%s': %d", sc.cmd.String(), errorCode)
				}

				if _, ok := err.(*ssh.ExitMissingError); ok {
					logrus.Warnf("Found exit missing error of command '%s'", sc.cmd.String())
					errorCode = -2
				}

				if _, ok := err.(net.Error); ok {
					logrus.WithContext(ctx).Debugf("Found network error running command '%s'", sc.cmd.String())
					errorCode = 255
				}

				results <- result{
					errorcode: errorCode,
					stdout:    b.String(),
					stderr:    be.String(),
					reserr:    err,
				}
				return
			}

			breaker = true
		}

		results <- result{
			errorcode: errorCode,
			stdout:    b.String(),
			stderr:    be.String(),
			reserr:    nil,
		}
	}()

	if timeout != 0 {
		select {
		case res := <-results:
			if outs == outputs.DISPLAY {
				fmt.Print(res.stdout)
				fmt.Print(res.stderr)
			}
			return res.errorcode, res.stdout, res.stderr, nil
		case <-enough:
			return 255, "", "", fail.NewError("received timeout of %s", timeout)
		case <-ctx.Done():
			return 255, "", "", fail.ConvertError(ctx.Err())
		}
	}

	select {
	case res := <-results:
		if outs == outputs.DISPLAY {
			fmt.Print(res.stdout)
			fmt.Print(res.stderr)
		}

		return res.errorcode, res.stdout, res.stderr, nil
	case <-ctx.Done():
		return 255, "", "", fail.ConvertError(ctx.Err())
	}
}

func (sc *LibCommand) cleanup() error {
	err1 := sc.closeTunneling()
	if err1 != nil {
		return fmt.Errorf("unable to close SSH tunnels: %s", err1.Error())
	}

	return nil
}

// Close this function exists only to provide compatibility with previous SSH api
func (sc *LibCommand) Close() fail.Error {
	return fail.ConvertError(sc.cleanup())
}

// CreateTunneling ...
func (sconf *Profile) CreateTunneling(ctx context.Context) (*sshtunnel.SSHTunnel, *Profile, error) {
	var tu *sshtunnel.SSHTunnel

	if sconf.LocalHost == "" {
		sconf.LocalHost = ssh2.Loopback
	}

	internalPort := ssh2.SSHPort // all machines use port 22...
	var gateway *sshtunnel.Endpoint
	var altgateway *sshtunnel.Endpoint
	var remote bool

	if sconf.GatewayConfig == nil { // it has to be a gateway
		internalPort = sconf.Port // ... except maybe the gateway itself

		var rerr error
		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", sconf.User, sconf.IPAddress, sconf.Port),
			sshtunnel.EndpointOptionKeyFromString(sconf.PrivateKey, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	} else {
		var rerr error
		remote = true

		scu, _ := sconf.GatewayConfig.GetUser()
		sci, _ := sconf.GatewayConfig.GetIPAddress()
		scp, _ := sconf.GatewayConfig.GetPort()
		scpk, _ := sconf.GatewayConfig.GetPrivateKey()

		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", scu, sci, scp),
			sshtunnel.EndpointOptionKeyFromString(scpk, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	}

	if sconf.SecondaryGatewayConfig != nil {
		var rerr error
		remote = true

		scu, _ := sconf.SecondaryGatewayConfig.GetUser()
		sci, _ := sconf.SecondaryGatewayConfig.GetIPAddress()
		scp, _ := sconf.SecondaryGatewayConfig.GetPort()
		scpk, _ := sconf.SecondaryGatewayConfig.GetPrivateKey()

		altgateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", scu, sci, scp),
			sshtunnel.EndpointOptionKeyFromString(scpk, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	}

	if remote {
		sci, _ := sconf.GatewayConfig.GetIPAddress()
		scp, _ := sconf.GatewayConfig.GetPort()
		if !netutils.CheckRemoteTCP(sci, int(scp)) {
			if !valid.IsNil(sconf.SecondaryGatewayConfig) {
				sci, _ := sconf.SecondaryGatewayConfig.GetIPAddress()
				scp, _ := sconf.SecondaryGatewayConfig.GetPort()
				if !netutils.CheckRemoteTCP(sci, int(scp)) {
					return nil, nil, fail.NewError("No direct connection to any gateway")
				}
			} else {
				return nil, nil, fail.NewError("No direct connection to any gateway")
			}
			gateway = altgateway // connect through alternative gateway
		}
	}

	server, err := sshtunnel.NewEndpoint(fmt.Sprintf("%s:%d", sconf.IPAddress, internalPort),
		sshtunnel.EndpointOptionKeyFromString(sconf.PrivateKey, ""))
	if err != nil {
		return nil, nil, err
	}
	local, err := sshtunnel.NewEndpoint(fmt.Sprintf("localhost:%d", sconf.LocalPort))
	if err != nil {
		return nil, nil, err
	}
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithLogger(log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)), sshtunnel.TunnelOptionWithDefaultKeepAlive())
		if err != nil {
			return nil, nil, err
		}
	} else {
		tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithDefaultKeepAlive())
		if err != nil {
			return nil, nil, err
		}
	}

	go func() {
		tsErr := tu.Start()
		if tsErr != nil {
			logrus.WithContext(ctx).Tracef("tunnel Start goroutine failed: %s", tsErr.Error())
		}
		logrus.WithContext(ctx).Tracef("quitting tunnel Start goroutine")
		tu.Close()
	}()

	tunnelReady := <-tu.Ready()
	if !tunnelReady {
		return nil, nil, fmt.Errorf("unable to establish tunnel")
	}

	return tu, sconf, nil
}

// Command returns the cmd struct to execute cmdString remotely
func (sconf *Profile) Command(cmdString string) (*LibCommand, fail.Error) {
	return sconf.command(cmdString, false, false)
}

// NewCommand returns the cmd struct to execute cmdString remotely
func (sconf *Profile) NewCommand(_ context.Context, cmdString string) (sshapi.Command, fail.Error) {
	return sconf.command(cmdString, false, false)
}

// SudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sconf *Profile) SudoCommand(cmdString string) (*LibCommand, fail.Error) {
	return sconf.command(cmdString, false, true)
}

// NewSudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sconf *Profile) NewSudoCommand(_ context.Context, cmdString string) (sshapi.Command, fail.Error) {
	return sconf.command(cmdString, false, true)
}

func (sconf *Profile) command(cmdString string, withTty, withSudo bool) (*LibCommand, fail.Error) {
	cmd := exec.Command(cmdString)
	sshCommand := LibCommand{
		withSudo: withSudo,
		username: "",
		cfg:      sconf,
		cmd:      cmd,
	}
	return &sshCommand, nil
}

// WaitServerReady waits until the SSH server is ready
// the 'timeout' parameter is in minutes
func (sconf *Profile) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, err fail.Error) {
	if sconf == nil {
		return "", fail.InvalidInstanceError()
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sconf.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sc.Host", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("ssh"), "(%s, %s)", phase, temporal.FormatDuration(timeout)).WithStopwatch().Entering()
	defer tracer.Exiting()

	// no timeout is unsafe, we set an upper limit
	if timeout == 0 {
		timeout = temporal.HostLongOperationTimeout()
	}

	originalPhase := phase
	if phase == "ready" { // FIXME: Hardcoded strings
		phase = "final"
	}

	var (
		stdout, stderr string
	)

	retcode := -1
	iterations := 0
	begins := time.Now()
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-time.After(temporal.DefaultDelay()):
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			}

			retcode = -1
			iterations++

			cmd, _ := sconf.Command(fmt.Sprintf("sudo cat %s/user_data.%s.done", utils.StateFolder, phase))

			var xerr fail.Error
			retcode, stdout, stderr, xerr = cmd.RunWithTimeout(ctx, outputs.COLLECT, 60*time.Second) // FIXME: Remove hardcoded timeout
			if xerr != nil {
				if phase == "init" {
					logrus.Debugf("SSH still not ready for %s, phase %s", sconf.Hostname, phase)
				}
				return xerr
			}

			if retcode != 0 {
				if phase == "init" {
					logrus.Debugf("SSH still not ready for %s, phase %s", sconf.Hostname, phase)
				}
				fe := fail.NewError("remote SSH NOT ready: error code: %d", retcode)
				fe.Annotate("retcode", retcode)
				fe.Annotate("stdout", stdout)
				fe.Annotate("stderr", stderr)
				fe.Annotate("operation", cmd.Display())
				fe.Annotate("iterations", iterations)
				return fe
			}

			return nil
		},
		0,
		timeout+time.Minute,
	)
	if retryErr != nil {
		logrus.WithContext(ctx).Debugf("WaitServerReady: the wait of %s finished with: %v", sconf.Hostname, retryErr)
		return stdout, retryErr
	}

	if !strings.HasPrefix(stdout, "0,") {
		return stdout, fail.NewError("PROVISIONING ERROR: host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.IPAddress, originalPhase,
			temporal.FormatDuration(time.Since(begins)), stdout)
	}

	logrus.WithContext(ctx).Debugf(
		"host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.IPAddress, originalPhase,
		temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// CopyWithTimeout ...
func (sconf *Profile) CopyWithTimeout(ctx context.Context, remotePath string, localPath string, isUpload bool, timeout time.Duration) (int, string, string, fail.Error) {
	if ctx == nil {
		return -1, "", "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	if timeout == 0 {
		return -1, "", "", fail.InvalidParameterCannotBeNilError("timeout")
	}

	currentCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		code   int
		stdout string
		stderr string
		err    error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		ac, ao, ae, err := sconf.copy(currentCtx, remotePath, localPath, isUpload)
		chRes <- result{
			code:   ac,
			stdout: ao,
			stderr: ae,
			err:    err,
		}
	}()

	select {
	case res := <-chRes: // if it works return the return
		return res.code, res.stderr, res.stderr, fail.Wrap(res.err)
	case <-ctx.Done(): // if not because parent context was canceled
	case <-currentCtx.Done(): // or timeout hits
	}

	// wait anyway until call it's finished, then return an error
	// if sc.Copy can handle contexts well, we don't have to wait until it's finished
	// however is not the case here
	select {
	case <-chRes:
	case <-time.After(5 * time.Second): // grace period
	}

	if ctx.Err() != nil {
		return -1, "", "", fail.Wrap(ctx.Err())
	}

	if currentCtx.Err() != nil {
		return -1, "", "", fail.Wrap(currentCtx.Err())
	}

	return -1, "", "", fail.NewError("timeout copying...")
}

func closeAndLog(in io.Closer) {
	if in != nil {
		err := in.Close()
		if err != nil {
			logrus.WithContext(context.Background()).Tracef(err.Error())
		}
	}
}

func closeAndIgnore(in io.Closer) { // nolint
	if in != nil {
		_ = in.Close()
	}
}

// Copy copies a file/directory from/to local to/from remote
func (sconf *Profile) copy(ctx context.Context, remotePath string, localPath string, isUpload bool) (int, string, string, fail.Error) {
	tu, sshConfig, err := sconf.CreateTunneling(ctx)
	if err != nil {
		return -1, "", "", fail.NewError("unable to create tunnels : %s", err.Error())
	}
	defer func() {
		if tu != nil {
			tu.Close()
		}
	}()

	pk, err := sshtunnel.AuthMethodFromPrivateKey([]byte(sshConfig.PrivateKey), nil)
	if err != nil {
		return -1, "", "", fail.Wrap(err)
	}

	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			pk,
		},
		HostKeyCallback: sshtunnel.TrustedHostKeyCallback(""),
	}

	if isUpload {
		// connect
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshConfig.LocalHost, tu.GetLocalEndpoint().Port()), config)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(conn)

		// create new SFTP client
		client, err := sftp.NewClient(conn)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(client)

		// create destination file
		dstFile, err := client.Create(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(dstFile)

		// create source file
		srcFile, err := os.Open(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(srcFile)

		// copy source file to destination file
		written, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}

		var expected int64
		if fi, err := srcFile.Stat(); err != nil {
			if fi != nil {
				expected = fi.Size()
				if fi.Size() != written {
					return -1, "", "", fail.NewError("file size mismatch")
				}
			}
		}

		// it seems copy was ok, but make sure of it
		finfo, err := client.Lstat(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		if expected != 0 {
			if finfo.Size() == 0 {
				return -1, "", "", fail.NewError("problem checking file %s: empty file", remotePath)
			}
		}

		logrus.WithContext(ctx).Debugf("%d bytes copied to %s\n", written, remotePath)
	} else {
		// connect
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshConfig.LocalHost, tu.GetLocalEndpoint().Port()), config)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(conn)

		// create new SFTP client
		client, err := sftp.NewClient(conn)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(client)

		// create destination file
		dstFile, err := os.Create(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(dstFile)

		// open source file
		srcFile, err := client.Open(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer closeAndLog(srcFile)

		// copy source file to destination file
		written, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		logrus.WithContext(ctx).Debugf("%d bytes copied from %s\n", written, remotePath)

		if fi, err := srcFile.Stat(); err != nil {
			if fi != nil {
				if fi.Size() != written {
					return -1, "", "", fail.NewError("file size mismatch")
				}
			}
		}

		// flush in-memory copy
		err = dstFile.Sync()
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
	}

	return 0, "", "", nil
}

// Enter runs interactive shell
func (sconf *Profile) Enter(ctx context.Context, username string, shell string) (ferr fail.Error) {
	userPass := ""
	if username != "" && username != sconf.User {
		fmt.Printf("Password: ")
		up, err := terminal.ReadPassword(0)
		if err != nil {
			return fail.ConvertError(err)
		}
		userPass = string(up)
	}

	sshUsername := username
	if username == "" {
		sshUsername = sconf.User
	}

	tu, sshConfig, err := sconf.CreateTunneling(context.Background())
	if err != nil {
		return fail.ConvertError(fmt.Errorf("unable to create tunnels : %s", err.Error()))
	}
	defer func() {
		if tu != nil {
			tu.Close()
		}
	}()

	pk, err := sshtunnel.AuthMethodFromPrivateKey([]byte(sshConfig.PrivateKey), nil)
	if err != nil {
		return fail.ConvertError(err)
	}

	config := &ssh.ClientConfig{
		User: sconf.User, // It should be sshUsername, but we assume no other sc users are allowed
		Auth: []ssh.AuthMethod{
			pk,
		},
		Timeout:         7 * time.Second,
		HostKeyCallback: sshtunnel.TrustedHostKeyCallback(""),
	}

	hostport := fmt.Sprintf("%s:%d", "localhost", tu.GetLocalEndpoint().Port())
	conn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		return fail.ConvertError(fmt.Errorf("cannot connect %v: %w", hostport, err))
	}
	defer func() {
		_ = conn.Close()
	}()

	session, err := conn.NewSession()
	if err != nil {
		return fail.ConvertError(fmt.Errorf("cannot open new session: %w", err))
	}
	defer func() {
		_ = session.Close()
	}()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return fail.ConvertError(fmt.Errorf("terminal make raw: %s", err))
	}
	defer func() {
		_ = terminal.Restore(fd, state)
	}()

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return fail.ConvertError(fmt.Errorf("terminal get size: %s", err))
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	if err := session.RequestPty(term, h, w, modes); err != nil {
		return fail.ConvertError(fmt.Errorf("session xterm: %s", err))
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// AcceptEnv DEBIAN_FRONTEND
	if sshUsername != "safescale" {
		err = session.Setenv("SAFESCALESSHUSER", sshUsername)
		if err != nil {
			logrus.WithContext(ctx).Debugf("failure setting user terminal: %v", err)
		}
		err = session.Setenv("SAFESCALESSHPASS", userPass)
		if err != nil {
			logrus.WithContext(ctx).Debugf("failure setting user password: %v", err)
		}
	}

	if err := session.Shell(); err != nil {
		return fail.ConvertError(fmt.Errorf("session shell: %s", err))
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() { // nolint
			case 130:
				return nil
			}
		}
		return fail.ConvertError(fmt.Errorf("sc: %s", err))
	}

	return nil
}

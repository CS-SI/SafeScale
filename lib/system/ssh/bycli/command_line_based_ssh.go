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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bycli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
//
//	To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
//	use the same port for all access to a same host (not the case currently)
//	May not be used for interactive ssh connection...
const (
	sshOptions = "-q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
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

func NewProfile(hostname string, ipAddress string, port int, user string, privateKey string, localPort int, localHost string, gatewayConfig sshapi.Config, secondaryGatewayConfig sshapi.Config) *Profile {
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

	return NewProfile(hostname, IPAddress, int(port), user, privateKey, int(localPort), localHost, gatewayConfig, secondaryGatewayConfig), nil
}

func (sconf *Profile) Config() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf, nil
}

// IsNull tells if the instance is a null value
func (sconf *Profile) IsNull() bool {
	return sconf == nil || sconf.IPAddress == ""
}

func (sconf *Profile) GetUser() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.User, nil
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

// Clone clones the Profile
func (sconf *Profile) Clone() *Profile {
	out := &Profile{}
	*out = *sconf
	return out
}

// Tunnel a SSH tunnel
type Tunnel struct {
	port      int
	cmd       *exec.Cmd
	cmdString string
	keyFile   *os.File
}

type Tunnels []*Tunnel

// Close closes ssh tunnel
func (stun *Tunnel) Close() fail.Error {
	defer func() {
		_ = utils.LazyRemove(stun.keyFile.Name())
	}()

	xerr := killProcess(stun.cmd.Process)
	if xerr != nil {
		return xerr
	}

	// Kills remaining processes if there are some
	bytesCmd, err := exec.Command("pgrep", "-f", stun.cmdString).Output()
	if err != nil {
		_, code, problem := utils.ExtractRetCode(err)
		if problem != nil {
			return fail.Wrap(err, "unable to close tunnel, running pgrep")
		}
		if code == 1 { // no process found
			return nil
		}
		if code == 127 { // pgrep not installed
			return nil
		}
		return fail.Wrap(err, "unable to close tunnel, unexpected errorcode running pgrep: %d", code)
	}

	portStr := strings.Trim(string(bytesCmd), "\n")
	if _, err = strconv.Atoi(portStr); err != nil {
		return fail.Wrap(err, "unable to close tunnel")
	}

	if err = exec.Command("kill", "-9", portStr).Run(); err != nil {
		return fail.Wrap(err, "unable to close tunnel: %s", fmt.Sprintf("kill -9 failed: %s", reflect.TypeOf(err).String()))
	}

	return nil
}

// killProcess sends a kill signal to the process passed as parameter and Wait() for it to release resources (and
// prevent zombie...)
func killProcess(proc *os.Process) fail.Error {
	err := proc.Kill()
	if err != nil {
		switch cerr := err.(type) {
		case syscall.Errno:
			switch cerr {
			case syscall.ESRCH:
				// process not found, continue
			default:
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		default:
			switch err.Error() {
			case "os: process already finished":
			default:
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		}
	}

	_, err = proc.Wait()
	if err != nil {
		switch cerr := err.(type) {
		case *os.SyscallError:
			err = cerr.Err
		default:
		}
		switch err {
		case syscall.ESRCH, syscall.ECHILD:
			// process not found or has no child, continue
		default:
			return fail.Wrap(err, "unable to wait on SSH tunnel process")
		}
	}

	return nil
}

// Close closes all the tunnels
func (tunnels Tunnels) Close() fail.Error {
	var errorList []error
	for _, t := range tunnels {
		if xerr := t.Close(); xerr != nil {
			errorList = append(errorList, xerr)
		}
	}
	if len(errorList) > 0 {
		return fail.NewErrorList(errorList)
	}

	return nil
}

// GetFreePort get a free port
func getFreePort() (uint, fail.Error) {
	listener, err := net.Listen("tcp", ":0")
	defer func() {
		clErr := listener.Close()
		if clErr != nil {
			logrus.WithContext(context.Background()).Error(clErr)
		}
	}()
	if err != nil {
		return 0, fail.NewError(err.Error())
	}
	tcp, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fail.NewError("invalid listener.Addr()")
	}

	port := tcp.Port
	return uint(port), nil
}

// isTunnelReady tests if the port used for the tunnel is reserved
// If yes, the tunnel is ready, otherwise it failed
func isTunnelReady(port int) bool {
	// Try to create a server with the port
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ssh.Loopback, port))
	if err != nil {
		return true
	}
	err = server.Close()
	if err != nil {
		logrus.WithContext(context.Background()).Warnf("Error closing server: %v", err)
	}
	return false
}

// buildTunnel create SSH from local host to remote host through gateway
// if localPort is set to 0 then it's automatically chosen
func buildTunnel(scfg sshapi.Config) (*Tunnel, fail.Error) {
	if valid.IsNil(scfg) {
		return nil, fail.InvalidParameterCannotBeNilError("scfg")
	}

	gwCfg, xerr := scfg.GetPrimaryGatewayConfig()
	if xerr != nil {
		return nil, xerr
	}

	// Creates temporary file with private key
	scpk, xerr := gwCfg.GetPrivateKey()
	if xerr != nil {
		return nil, xerr
	}

	f, err := utils.CreateTempFileFromString(scpk, 0400)
	if err != nil {
		return nil, err
	}

	localPort, xerr := scfg.GetLocalPort()
	if xerr != nil {
		return nil, xerr
	}

	if localPort == 0 {
		localPort, err = getFreePort()
		if err != nil {
			return nil, err
		}
	}

	targetPort, xerr := scfg.GetPort()
	if xerr != nil {
		return nil, xerr
	}

	gwPort, xerr := gwCfg.GetPort()
	if xerr != nil {
		return nil, xerr
	}

	if targetPort == 0 {
		targetPort = ssh.SSHPort
	}
	if gwPort == 0 {
		gwPort = ssh.SSHPort
	}

	// VPL: never used
	// if scfg.SecondaryGatewayConfig != nil && scfg.SecondaryGatewayConfig.Port == 0 {
	// 	scfg.SecondaryGatewayConfig.Port = 22
	// }

	targetHost, xerr := scfg.GetHostname()
	if xerr != nil {
		return nil, xerr
	}

	targetIPAddr, xerr := scfg.GetIPAddress()
	if xerr != nil {
		return nil, xerr
	}

	gwUser, xerr := gwCfg.GetUser()
	if xerr != nil {
		return nil, xerr
	}

	gwIPAddr, xerr := gwCfg.GetIPAddress()
	if xerr != nil {
		return nil, xerr
	}

	options := sshOptions + " -oServerAliveInterval=60 -oServerAliveCountMax=10" // this survives 10 minutes without connection
	cmdString := fmt.Sprintf(
		"ssh -i \"%s\" -NL %s:%d:%s:%d %s@%s %s -oSendEnv='IAM=%s' -p %d",
		f.Name(),
		ssh.Loopback,
		localPort,
		targetIPAddr,
		targetPort,
		gwUser,
		gwIPAddr,
		options,
		targetHost,
		gwPort,
	)

	// logrus.WithContext(context.Background()).Tracef("Creating SSH tunnel with '%s'", cmdString)

	cmd := exec.Command("bash", "-c", cmdString)
	cmd.SysProcAttr = getSyscallAttrs()
	cerr := cmd.Start()
	if cerr != nil {
		return nil, fail.ConvertError(cerr)
	}

	// gives 10s to build a tunnel, 1s is not enough as the number of tunnels keeps growing
	for nbiter := 0; !isTunnelReady(int(localPort)) && nbiter < 100; nbiter++ {
		time.Sleep(100 * time.Millisecond)
	}

	if !isTunnelReady(int(localPort)) {
		xerr := fail.NotAvailableError("the tunnel is not ready")
		derr := killProcess(cmd.Process)
		if derr != nil {
			_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to kill SSH process"))
		}
		return nil, xerr
	}

	return &Tunnel{
		port:      int(localPort),
		cmd:       cmd,
		cmdString: cmdString,
		keyFile:   f,
	}, nil
}

// CliCommand defines a SSH command
type CliCommand struct {
	hostname     string
	runCmdString string
	cmd          *exec.Cmd
	tunnels      Tunnels
	keyFile      *os.File
}

// Wait waits for the command to exit and waits for any copying to stdin or copying from stdout or stderr to complete.
// The command must have been started by Start.
// The returned error is nil if the command runs, has no problems copying stdin, stdout, and stderr, and exits with a zero exit status.
// If the command fails to run or doesn't complete successfully, the error is of type *ExitError. Other error types may be returned for I/O problems.
// Wait also waits for the I/O loop copying from c.Stdin into the process's standard input to complete.
// Wait does not release resources associated with the cmd; Command.Close() must be called for that.
// !!!WARNING!!!: the error returned is NOT USING fail.Error because we may NEED TO CAST the error to recover return code
func (scmd *CliCommand) Wait() error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	return scmd.cmd.Wait()
}

func (scmd *CliCommand) String() string {
	return scmd.runCmdString
}

// Kill kills Command process.
func (scmd *CliCommand) Kill() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}
	if scmd.cmd.Process == nil {
		return fail.InvalidInstanceContentError("scmd.cmd.Process", "cannot be nil")
	}

	return killProcess(scmd.cmd.Process)
}

// getStdoutPipe returns a pipe that will be connected to the command's standard output when the command starts.
// Wait will close the pipe after seeing the command exit, so most callers does not need to close the pipe themselves; however,
// an implication is that it is incorrect to call Wait before all reads from the pipe have been completed.
// For the same reason, it is incorrect to call Run when using getStdoutPipe.
func (scmd *CliCommand) getStdoutPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdoutPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// getStderrPipe returns a pipe that will be connected to the Command's standard error when the Command starts.
// Wait will close the pipe after seeing the Command exit, so most callers does not need to close the pipe themselves; however,
// an implication is that it is incorrect to call Wait before all reads from the pipe have completed. For the same reason,
// it is incorrect to use Run when using getStderrPipe.
func (scmd *CliCommand) getStderrPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StderrPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// getStdinPipe returns a pipe that will be connected to the Command's standard input when the command starts.
// The pipe will be closed automatically after Wait sees the Command exit.
// A caller need only call Close to force the pipe to close sooner.
// For example, if the command being run will not exit until standard input is closed, the caller must close the pipe.
func (scmd *CliCommand) getStdinPipe() (io.WriteCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdinPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// Output returns the standard output of command started.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (scmd *CliCommand) Output() ([]byte, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	content, err := scmd.cmd.Output()
	if err != nil {
		return nil, fail.NewError(err.Error())
	}
	return content, nil
}

// CombinedOutput returns the combined standard of command started
// output and standard error.
func (scmd *CliCommand) CombinedOutput() ([]byte, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	content, err := scmd.cmd.CombinedOutput()
	if err != nil {
		return nil, fail.NewError(err.Error())
	}
	return content, nil
}

// Start starts the specified command but does not wait for it to complete.
// The Wait method will wait for completion and return the exit code.
func (scmd *CliCommand) Start() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	if err := scmd.cmd.Start(); err != nil {
		return fail.ConvertError(err)
	}
	return nil
}

// RunWithTimeout ...
// returns:
//   - retcode int
//   - stdout string
//   - stderr string
//   - xerr fail.Error
//     . *fail.ErrNotAvailable if remote SSH is not available
//     . *fail.ErrTimeout if 'timeout' is reached
//
// Note: if you want to RunWithTimeout in a loop, you MUST create the scmd inside the loop, otherwise
//
//	you risk to call twice os/exec.Wait, which may panic
func (scmd *CliCommand) RunWithTimeout(inctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()
	const invalid = -1

	type result struct {
		ra   int
		rb   string
		rc   string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		if scmd == nil {
			chRes <- result{invalid, "", "", fail.InvalidInstanceError()}
			return
		}
		if ctx == nil {
			chRes <- result{invalid, "", "", fail.InvalidParameterError("ctx", "cannot be nil")}
			return
		}

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
		tracer.Trace("host='%s', command=%s", scmd.hostname, scmd.runCmdString)
		defer tracer.Exiting()

		subtask := new(errgroup.Group)

		if timeout == 0 {
			timeout = 1200 * time.Second // upper bound of 20 min
		} else if timeout > 1200*time.Second {
			timeout = 1200 * time.Second // nothing should take more than 20 min
		}

		trch := make(chan interface{}, 1)
		subtask.Go(func() error {
			tctx, cat := context.WithTimeout(ctx, timeout)
			defer cat()
			tr, xerr := scmd.taskExecute(tctx, taskExecuteParameters{collectOutputs: outs != outputs.DISPLAY})
			trch <- tr
			return xerr
		})

		xerr := fail.ConvertError(subtask.Wait())
		if xerr != nil {
			defer close(trch)

			switch xerr.(type) {
			case *fail.ErrTimeout:
				xerr = fail.Wrap(fail.Cause(xerr), "reached timeout of %s", temporal.FormatDuration(timeout)) // FIXME: Change error message
			default:
			}

			// FIXME: This kind of resource exhaustion deserves its own handling and its own kind of error
			{
				if strings.Contains(xerr.Error(), "annot allocate memory") {
					chRes <- result{invalid, "", "", fail.AbortedError(xerr, "problem allocating memory, pointless to retry")}
					return
				}

				if strings.Contains(xerr.Error(), "esource temporarily unavailable") {
					chRes <- result{invalid, "", "", fail.AbortedError(xerr, "not enough resources, pointless to retry")}
					return
				}
			}

			tracer.Trace("run failed: %v", xerr)
			chRes <- result{invalid, "", "", xerr}
			return
		}

		close(trch)
		r := <-trch
		if res, ok := r.(data.Map); ok {
			tracer.Trace("run succeeded, retcode=%d", res["retcode"].(int))
			chRes <- result{res["retcode"].(int), res["stdout"].(string), res["stderr"].(string), nil}
			return
		}
		chRes <- result{invalid, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")}
	}()
	select {
	case res := <-chRes:
		return res.ra, res.rb, res.rc, res.rErr
	case <-ctx.Done():
		return invalid, "", "", fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return invalid, "", "", fail.ConvertError(inctx.Err())
	}
}

type taskExecuteParameters struct {
	collectOutputs bool
}

func (scmd *CliCommand) taskExecute(inctx context.Context, p interface{}) (interface{}, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rRes interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, gerr := func() (_ interface{}, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			params, ok := p.(taskExecuteParameters)
			if !ok {
				return nil, fail.InvalidParameterError("p", "must be a 'taskExecuteParameters'")
			}

			var (
				stdoutBridge, stderrBridge cli.PipeBridge
				pipeBridgeCtrl             *cli.PipeBridgeController
				msgOut, msgErr             []byte
				xerr                       fail.Error
				err                        error
			)

			remap := data.Map{
				"retcode": -1,
				"stdout":  "",
				"stderr":  "",
			}

			// Prepare command
			scmd.cmd = exec.CommandContext(ctx, "bash", "-c", scmd.runCmdString)
			scmd.cmd.SysProcAttr = getSyscallAttrs()

			// Set up the outputs (std and err)
			stdoutPipe, xerr := scmd.getStdoutPipe()
			if xerr != nil {
				return remap, xerr
			}

			stderrPipe, xerr := scmd.getStderrPipe()
			if xerr != nil {
				return remap, xerr
			}

			if !params.collectOutputs {
				if stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe); xerr != nil {
					return remap, xerr
				}

				if stderrBridge, xerr = cli.NewStderrBridge(stderrPipe); xerr != nil {
					return remap, xerr
				}

				if pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge); xerr != nil {
					return remap, xerr
				}

				// Starts pipebridge if needed
				if xerr = pipeBridgeCtrl.Start(ctx); xerr != nil {
					return remap, xerr
				}
			}

			// Launch the command and wait for its completion
			if xerr = scmd.Start(); xerr != nil {
				return remap, xerr
			}

			if params.collectOutputs {
				if msgOut, err = io.ReadAll(stdoutPipe); err != nil {
					return remap, fail.ConvertError(err)
				}

				if msgErr, err = io.ReadAll(stderrPipe); err != nil {
					return remap, fail.ConvertError(err)
				}
			}

			var pbcErr error
			runErr := scmd.Wait()
			_ = stdoutPipe.Close()
			_ = stderrPipe.Close()

			if runErr != nil {
				xerr = fail.ExecutionError(runErr)
				// If error doesn't contain outputs and return code of the process, stop the pipe bridges and return error
				var (
					rc     int
					note   data.Annotation
					stderr string
					ok     bool
				)
				if note, ok = xerr.Annotation("retcode"); !ok {
					if !params.collectOutputs {
						if derr := pipeBridgeCtrl.Stop(); derr != nil {
							_ = xerr.AddConsequence(derr)
						}
					}
					return remap, xerr
				} else if rc, ok = note.(int); ok && rc == -1 {
					if !params.collectOutputs {
						if derr := pipeBridgeCtrl.Stop(); derr != nil {
							_ = xerr.AddConsequence(derr)
						}
					}
					return remap, xerr
				}

				remap["retcode"], ok = note.(int)
				if !ok {
					logrus.WithContext(ctx).Warnf("Unable to recover 'retcode' because 'note' is not an integer: %v", note)
				}

				// Make sure all outputs have been processed
				if !params.collectOutputs {
					if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
						logrus.WithContext(ctx).Error(pbcErr.Error())
					}

					if note, ok = xerr.Annotation("stderr"); ok {
						remap["stderr"], ok = note.(string)
						if !ok {
							logrus.WithContext(ctx).Warnf("Unable to recover 'stederr' because 'note' is not an string: %v", note)
						}
					}
				} else {
					remap["stdout"] = string(msgOut)
					remap["stderr"] = fmt.Sprint(string(msgErr), stderr)
				}
			} else {
				remap["retcode"] = 0
				if params.collectOutputs {
					remap["stdout"] = string(msgOut)
					remap["stderr"] = string(msgErr)
				} else if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
					logrus.WithContext(ctx).Error(pbcErr.Error())
				}
			}

			return remap, nil

		}()
		chRes <- result{gres, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rRes, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// Close is called to clean Command (close tunnel(s), remove temporary files, ...)
func (scmd *CliCommand) Close() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}

	var err1 error

	if len(scmd.tunnels) > 0 {
		err1 = scmd.tunnels.Close()
	}
	if err1 != nil {
		defer func() { // lazy removal
			_ = utils.LazyRemove(scmd.keyFile.Name())
		}()
		return fail.Wrap(err1, "failed to close SSH tunnels")
	}

	err2 := utils.LazyRemove(scmd.keyFile.Name())
	if err2 != nil {
		return fail.Wrap(err2, "failed to close SSH tunnels")
	}
	return nil
}

// createConsecutiveTunnels creates recursively all the SSH tunnels hops needed to reach the remote
func createConsecutiveTunnels(sc sshapi.Config, tunnels *Tunnels) (*Tunnel, fail.Error) {
	if sc != nil {
		// determine what gateway to use
		var gwConf sshapi.Config

		gwConf, xerr := sc.GetPrimaryGatewayConfig()
		if xerr != nil {
			return nil, xerr
		}

		sgwConf, xerr := sc.GetSecondaryGatewayConfig()
		if xerr != nil {
			return nil, xerr
		}

		if gwConf != nil {
			gwi, xerr := gwConf.GetIPAddress()
			if xerr != nil {
				return nil, xerr
			}
			gwp, xerr := gwConf.GetPort()
			if xerr != nil {
				return nil, xerr
			}

			if !netutils.CheckRemoteTCP(gwi, int(gwp)) {
				if !valid.IsNil(sgwConf) {
					gwConf = sgwConf
					gwi, xerr := sgwConf.GetIPAddress()
					if xerr != nil {
						return nil, xerr
					}
					gwp, xerr := sgwConf.GetPort()
					if xerr != nil {
						return nil, xerr
					}
					if !netutils.CheckRemoteTCP(gwi, int(gwp)) {
						return nil, fail.NotAvailableError("no gateway is available to establish a SSH tunnel")
					}
				} else {
					return nil, fail.NotAvailableError("no gateway is available to establish a SSH tunnel")
				}
			}
		}

		tunnel, xerr := createConsecutiveTunnels(gwConf, tunnels)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotAvailable:
				gwConf = sgwConf
				tunnel, xerr = createConsecutiveTunnels(gwConf, tunnels)
				if xerr != nil {
					return nil, xerr
				}
			default:
				return nil, xerr
			}
		}

		if gwConf != nil {
			cfg, _ := ssh.NewConfigFrom(sc)
			cfg.GatewayConfig = gwConf
			if tunnel != nil {
				gateway, _ := ssh.NewConfigFrom(gwConf)
				gateway.Port = tunnel.port
				gateway.IPAddress = ssh.Loopback
				cfg.GatewayConfig = gateway
			}

			failures := 0
			xerr = retry.WhileUnsuccessful(
				func() error {
					tunnel, xerr = buildTunnel(cfg)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotAvailable: // When this happens, resources are close to exhaustion
							failures++
							if failures > 6 { // TODO: retry lib should provide some kind of circuit-breaker pattern
								return retry.StopRetryError(xerr, "not enough resources, pointless to retry")
							}
							return xerr
						default:
							return xerr
						}
					}

					// Note: provokes LIFO (Last In First Out) during the deletion of tunnels
					*tunnels = append(Tunnels{tunnel}, *tunnels...)
					return nil
				},
				temporal.DefaultDelay(),
				temporal.OperationTimeout(),
			)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *retry.ErrStopRetry:
					return nil, fail.Wrap(fail.Cause(xerr))
				case *retry.ErrTimeout:
					return nil, fail.ConvertError(fail.Cause(xerr))
				}
				return nil, xerr
			}
			return tunnel, nil
		}
	}
	return nil, nil
}

func (sconf *Profile) CreatePersistentTunneling() (ferr fail.Error) {
	_, _, xerr := sconf.CreateTunneling()
	return xerr
}

// CreateTunneling ...
func (sconf *Profile) CreateTunneling() (_ Tunnels, _ *Profile, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var tunnels Tunnels
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := tunnels.Close()
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to close SSH tunnels"))
			}
		}
	}()

	tunnel, xerr := createConsecutiveTunnels(sconf, &tunnels)
	if xerr != nil {
		return nil, nil, xerr
	}

	sshConfig := *sconf
	if tunnel == nil {
		return nil, &sshConfig, nil
	}

	if sconf.GatewayConfig != nil {
		sshConfig.Port = tunnel.port
		sshConfig.IPAddress = ssh.Loopback
	}
	return tunnels, &sshConfig, nil
}

func createSSHCommand(
	sconf *Profile, cmdString, username, shell string, withTty, withSudo bool,
) (string, *os.File, fail.Error) {
	f, err := utils.CreateTempFileFromString(sconf.PrivateKey, 0400)
	if err != nil {
		return "", nil, fail.Wrap(err, "unable to create temporary key file")
	}

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", sconf.Hostname)
	sshCmdString := fmt.Sprintf("ssh -i \"%s\" %s -p %d %s@%s", f.Name(), options, sconf.Port, sconf.User, sconf.IPAddress)

	if shell == "" {
		shell = "bash"
	}
	cmd := ""
	if username != "" {
		// we want to force a password prompt for the user
		// a first ssh is issued dedicated to ask password and in case of a success a second ssh is issued to open a session via sudo on the user
		// it works this way for those reasons:
		//	 a direct ssh to the user would force the host admin to tweak ssh and weaken the security by mistake
		//   sudo can not be forced to ask the password unless you modify the sudoers file to do so
		//	 su may be used to ask password then launch a command but it launches a shell without tty (sudo for example would refuse to work)
		cmd = "su " + username + " -c exit && " + sshCmdString + " -t sudo -u " + username
		withTty = true
	}

	if withTty {
		// tty option is required for some command like ls
		sshCmdString += " -t"
	}

	if withSudo {
		if cmd == "" {
			// tty option is required for some command like ls
			cmd = "sudo"
		}
	}

	if cmd != "" {
		sshCmdString += " " + cmd + " " + shell
	}

	if cmdString != "" {
		sshCmdString += fmt.Sprintf(" <<'ENDSSH'\n%s\nENDSSH", cmdString)
	}

	// logrus.WithContext(context.Background()).Debugf("Created SSH command '%s'", strings.Replace(sshCmdString, "\n", "\t", -1))

	return sshCmdString, f, nil
}

// NewCommand returns the cmd struct to execute runCmdString remotely
func (sconf *Profile) NewCommand(ctx context.Context, cmdString string) (sshapi.Command, fail.Error) {
	return sconf.newCommand(ctx, cmdString, false, false)
}

// NewSudoCommand returns the cmd struct to execute runCmdString remotely. NewCommand is executed with sudo
func (sconf *Profile) NewSudoCommand(ctx context.Context, cmdString string) (sshapi.Command, fail.Error) {
	return sconf.newCommand(ctx, cmdString, false, true)
}

func (sconf *Profile) newCommand(
	ctx context.Context, cmdString string, withTty, withSudo bool,
) (*CliCommand, fail.Error) {
	if sconf == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cmdString = strings.TrimSpace(cmdString); cmdString == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("runCmdString")
	}

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to create SSH tunnel")
	}

	sshCmdString, keyFile, err := createSSHCommand(sshConfig, cmdString, "", "", withTty, withSudo)
	if err != nil {
		return nil, fail.Wrap(err, "unable to create command")
	}

	sshCommand := CliCommand{
		hostname:     sconf.Hostname,
		runCmdString: sshCmdString,
		tunnels:      tunnels,
		keyFile:      keyFile,
	}
	return &sshCommand, nil
}

// newCopyCommand does the same thing as newCommand for SCP actions
func (sconf *Profile) newCopyCommand(
	ctx context.Context, localPath, remotePath string, isUpload bool,
) (*CliCommand, fail.Error) {
	if sconf == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if localPath = strings.TrimSpace(localPath); localPath == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("localPath")
	}
	if remotePath = strings.TrimSpace(remotePath); localPath == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("localPath")
	}

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, xerr
	}

	sshCmdString, keyFile, xerr := createSCPCommand(sshConfig, localPath, remotePath, isUpload)
	if xerr != nil {
		return nil, xerr
	}

	sshCommand := CliCommand{
		hostname:     sconf.Hostname,
		runCmdString: sshCmdString,
		tunnels:      tunnels,
		keyFile:      keyFile,
	}
	return &sshCommand, nil
}

// createSCPCommand Creates the scp command to do the copy
func createSCPCommand(sconf *Profile, localPath, remotePath string, isUpload bool) (string, *os.File, fail.Error) {
	f, err := utils.CreateTempFileFromString(sconf.PrivateKey, 0400)
	if err != nil {
		return "", nil, fail.Wrap(err, "unable to create temporary key file")
	}

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", sconf.Hostname)

	sshCmdString := fmt.Sprintf("scp -i \"%s\" %s -P %d ", f.Name(), options, sconf.Port)
	if isUpload {
		sshCmdString += fmt.Sprintf("\"%s\" %s@%s:%s", localPath, sconf.User, sconf.IPAddress, remotePath)
	} else {
		sshCmdString += fmt.Sprintf("%s@%s:%s \"%s\"", sconf.User, sconf.IPAddress, remotePath, localPath)
	}

	return sshCmdString, f, nil
}

// WaitServerReady waits until the SSH server is ready
func (sconf *Profile) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if sconf == nil {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sconf.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sconf.IPAddress", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("ssh"), "('%s',%s)", phase, temporal.FormatDuration(timeout)).Entering().Exiting()
	defer fail.OnExitTraceError(ctx, &ferr, "timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, sconf.Hostname, temporal.FormatDuration(timeout))

	originalPhase := phase
	if phase == "ready" {
		phase = "final"
	}

	// no timeout is unsafe, we set an upper limit
	if timeout == 0 {
		timeout = temporal.HostLongOperationTimeout()
	}

	var (
		stdout, stderr string
	)

	retcode := -1
	iterations := 0
	begins := time.Now()
	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			select {
			case <-time.After(temporal.DefaultDelay()):
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			}

			iterations++

			var sshCmd sshapi.Command
			var innerXErr fail.Error
			defer func() {
				if sshCmd != nil {
					_ = sshCmd.Close()
				}
			}()

			// -- Try to see if 'phase' file exists... --
			sshCmd, innerXErr = sconf.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.%s.done", utils.VarFolder, phase))
			if innerXErr != nil {
				if phase == "init" {
					logrus.WithContext(ctx).Debugf("SSH still not ready for %s, phase %s", sconf.Hostname, phase)
				}
				return innerXErr
			}
			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 { // nolint
				if phase == "init" {
					logrus.WithContext(ctx).Debugf("SSH still not ready for %s, phase %s", sconf.Hostname, phase)
				}
				switch phase {
				case "final":
					var sshCmd sshapi.Command
					var innerXErr fail.Error
					defer func() {
						if sshCmd != nil {
							_ = sshCmd.Close()
						}
					}()

					// Before v21.05.0, final provisioning state is stored in user_data.phase2.done file, so try to see if legacy file exists...
					sshCmd, innerXErr = sconf.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.phase2.done", utils.VarFolder))
					if innerXErr != nil {
						return innerXErr
					}

					retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
					if innerXErr != nil {
						return innerXErr
					}
				default:
				}

				fe := fail.NewError("remote SSH NOT ready: error code: %d", retcode)
				fe.Annotate("retcode", retcode)
				fe.Annotate("stdout", stdout)
				fe.Annotate("stderr", stderr)
				fe.Annotate("operation", sshCmd.String())
				fe.Annotate("iterations", iterations)
				return fe
			}

			return nil
		},
		0,
		timeout+time.Minute,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return stdout, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return stdout, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return stdout, retryErr
		}
	}

	if !strings.HasPrefix(stdout, "0,") {
		return stdout, fail.NewError("PROVISIONING ERROR: host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.IPAddress, originalPhase,
			temporal.FormatDuration(time.Since(begins)), stdout)
	}

	logrus.WithContext(ctx).WithContext(ctx).Debugf(
		"host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.Hostname, originalPhase,
		temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// CopyWithTimeout copies a file/directory from/to local to/from remote, and fails after 'timeout'
func (sconf *Profile) CopyWithTimeout(
	ctx context.Context, remotePath, localPath string, isUpload bool, timeout time.Duration,
) (int, string, string, fail.Error) {
	return sconf.copy(ctx, remotePath, localPath, isUpload, timeout)
}

// copy copies a file/directory from/to local to/from remote, and fails after 'timeout' (if timeout > 0)
func (sconf *Profile) copy(
	ctx context.Context,
	remotePath, localPath string,
	isUpload bool,
	timeout time.Duration,
) (retcode int, stdout string, stderr string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	const invalid = -1

	sshCommand, xerr := sconf.newCopyCommand(ctx, localPath, remotePath, isUpload)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to create copy command")
	}

	// Do not forget to close sshCommand, allowing the SSH tunnel close and corresponding process cleanup
	defer func() {
		derr := sshCommand.Close()
		if derr != nil {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnel"))
			} else {
				ferr = derr
			}
		}
	}()

	return sshCommand.RunWithTimeout(ctx, outputs.COLLECT, timeout)
}

// Enter to interactive shell, aka 'safescale ssh connect'
func (sconf *Profile) Enter(ctx context.Context, username string, shell string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		if len(tunnels) > 0 {
			derr := tunnels.Close()
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnels"))
			}
		}
		return fail.Wrap(xerr, "unable to create tunnels")
	}

	// Do not forget to close tunnels...
	defer func() {
		derr := tunnels.Close()
		if derr != nil {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnels"))
			} else {
				ferr = derr
			}
		}
	}()

	sshCmdString, keyFile, xerr := createSSHCommand(sshConfig, "", username, shell, true, false)
	if xerr != nil {
		for _, t := range tunnels {
			if nerr := t.Close(); nerr != nil {
				logrus.WithContext(ctx).Warnf("Error closing SSH tunnel: %v", nerr)
			}
		}
		if keyFile != nil {
			if nerr := utils.LazyRemove(keyFile.Name()); nerr != nil {
				logrus.WithContext(ctx).Warnf("Error removing file %v", nerr)
			}
		}
		return fail.Wrap(xerr, "unable to create command")
	}

	defer func() {
		derr := utils.LazyRemove(keyFile.Name())
		if derr != nil {
			logrus.WithContext(ctx).Warnf("Error removing temporary file: %v", derr)
		}
	}()

	proc := exec.Command("bash", "-c", sshCmdString)
	// proc.SysProcAttr = getSyscallAttrs()
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	err := proc.Run()
	if err != nil {
		return fail.ExecutionError(err)
	}

	return nil
}

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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
//      To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
//      use the same port for all access to a same host (not the case currently)
//      May not be used for interactive ssh connection...
const (
	sshOptions = "-q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
)

// Profile helper to manage ssh session
type Profile struct {
	Hostname               string     `json:"hostname"`
	IPAddress              string     `json:"ip_address"`
	Port                   int        `json:"port"`
	User                   string     `json:"user"`
	PrivateKey             string     `json:"private_key"`
	LocalPort              int        `json:"-"`
	LocalHost              string     `json:"local_host"`
	GatewayConfig          ssh.Config `json:"primary_gateway_config,omitempty"`
	SecondaryGatewayConfig ssh.Config `json:"secondary_gateway_config,omitempty"`
}

func NewProfile(hostname string, IPAddress string, port int, user string, privateKey string, localPort int, localHost string, gatewayConfig *Profile, secondaryGatewayConfig *Profile) *Profile {
	return &Profile{Hostname: hostname, IPAddress: IPAddress, Port: port, User: user, PrivateKey: privateKey, LocalPort: localPort, LocalHost: localHost, GatewayConfig: gatewayConfig, SecondaryGatewayConfig: secondaryGatewayConfig}
}

func NewConnector(ac ssh.Config) (*Profile, fail.Error) {
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

func (sconf *Profile) Config() (ssh.Config, fail.Error) {
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

func (sconf *Profile) GetPrimaryGatewayConfig() (ssh.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.GatewayConfig, nil
}

func (sconf *Profile) GetSecondaryGatewayConfig() (ssh.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.SecondaryGatewayConfig, nil
}

func (sconf *Profile) GetGatewayConfig(num uint) (ssh.Config, fail.Error) {
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
	defer debug.NewTracer(context.Background(), true).Entering().Exiting()

	defer func() {
		if lazyErr := utils.LazyRemove(stun.keyFile.Name()); lazyErr != nil {
			logrus.Error(lazyErr)
		}
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
			debug.IgnoreError(err)
			return nil
		}
		if code == 127 { // pgrep not installed
			debug.IgnoreError(fmt.Errorf("pgrep not installed"))
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
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", cerr.Error())
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		default:
			switch err.Error() {
			case "os: process already finished":
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", err.Error())
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
			debug.IgnoreError(err)
		default:
			logrus.Error(err.Error())
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
			logrus.Error(clErr)
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

// CreateTempFileFromString creates a temporary file containing 'content'
func CreateTempFileFromString(content string, filemode os.FileMode) (*os.File, fail.Error) {
	defaultTmpDir := os.TempDir()

	f, err := ioutil.TempFile(defaultTmpDir, "")
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to create temporary file")
	}
	_, err = f.WriteString(content)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to wrote string to temporary file")
	}

	err = f.Chmod(filemode)
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to change temporary file access rights")
	}

	err = f.Close()
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to close temporary file")
	}

	// logrus.Tracef("New temporary file %s", f.Name())

	return f, nil
}

// isTunnelReady tests if the port used for the tunnel is reserved
// If yes, the tunnel is ready, otherwise it failed
func isTunnelReady(port int) bool {
	// Try to create a server with the port
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ssh.LocalHost, port))
	if err != nil {
		return true
	}
	err = server.Close()
	if err != nil {
		logrus.Warnf("Error closing server: %v", err)
	}
	return false
}

// buildTunnel create SSH from local host to remote host through gateway
// if localPort is set to 0 then it's automatically chosen
func buildTunnel(scfg ssh.Config) (*Tunnel, fail.Error) {
	if valid.IsNil(scfg) {
		return nil, fail.InvalidParameterCannotBeNilError("scfg")
	}

	gwCfg, _ := scfg.GetPrimaryGatewayConfig()

	// Creates temporary file with private key
	scpk, _ := gwCfg.GetPrivateKey()
	f, err := CreateTempFileFromString(scpk, 0400)
	if err != nil {
		return nil, err
	}

	localPort, _ := scfg.GetLocalPort()
	if localPort == 0 {
		localPort, err = getFreePort()
		if err != nil {
			return nil, err
		}
	}

	targetPort, _ := scfg.GetPort()
	gwPort, _ := gwCfg.GetPort()

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

	targetHost, _ := scfg.GetHostname()
	targetIPAddr, _ := scfg.GetIPAddress()

	gwUser, _ := gwCfg.GetUser()
	gwIPAddr, _ := gwCfg.GetIPAddress()

	options := sshOptions + " -oServerAliveInterval=60 -oServerAliveCountMax=10" // this survives 10 minutes without connection
	cmdString := fmt.Sprintf(
		"ssh -i \"%s\" -NL %s:%d:%s:%d %s@%s %s -oSendEnv='IAM=%s' -p %d",
		f.Name(),
		ssh.LocalHost,
		localPort,
		targetIPAddr,
		targetPort,
		gwUser,
		gwIPAddr,
		options,
		targetHost,
		gwPort,
	)

	logrus.Debugf("Creating SSH tunnel with '%s'", cmdString)

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

// Command defines a SSH command
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
// - retcode int
// - stdout string
// - stderr string
// - xerr fail.Error
//   . *fail.ErrNotAvailable if remote SSH is not available
//   . *fail.ErrTimeout if 'timeout' is reached
// Note: if you want to RunWithTimeout in a loop, you MUST create the scmd inside the loop, otherwise
//       you risk to call twice os/exec.Wait, which may panic
// FIXME: maybe we should move this method inside sshconfig directly with systematically created scmd...
func (scmd *CliCommand) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	const invalid = -1
	if scmd == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("host='%s', command=\n%s\n", scmd.hostname, scmd.runCmdString)
	defer tracer.Exiting()

	subtask, xerr := concurrency.NewTaskWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/ssh/run"))
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if timeout == 0 {
		timeout = 1200 * time.Second // upper bound of 20 min
	} else if timeout > 1200*time.Second {
		timeout = 1200 * time.Second // nothing should take more than 20 min
	}

	if _, xerr = subtask.StartWithTimeout(scmd.taskExecute, taskExecuteParameters{collectOutputs: outs != outputs.DISPLAY}, timeout); xerr != nil {
		return invalid, "", "", xerr
	}

	_, r, xerr := subtask.WaitFor(timeout)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			xerr = fail.Wrap(fail.Cause(xerr), "reached timeout of %s", temporal.FormatDuration(timeout)) // FIXME: Change error message
		default:
			debug.IgnoreError(xerr)
		}

		// FIXME: This kind of resource exhaustion deserves its own handling and its own kind of error
		{
			if strings.Contains(xerr.Error(), "annot allocate memory") {
				return invalid, "", "", fail.AbortedError(xerr, "problem allocating memory, pointless to retry")
			}

			if strings.Contains(xerr.Error(), "esource temporarily unavailable") {
				return invalid, "", "", fail.AbortedError(xerr, "not enough resources, pointless to retry")
			}
		}

		tracer.Trace("run failed: %v", xerr)
		return invalid, "", "", xerr
	}

	if result, ok := r.(data.Map); ok {
		tracer.Trace("run succeeded, retcode=%d", result["retcode"].(int))
		return result["retcode"].(int), result["stdout"].(string), result["stderr"].(string), nil
	}
	return invalid, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")
}

type taskExecuteParameters struct {
	// stdout, stderr io.ReadCloser
	collectOutputs bool
}

func (scmd *CliCommand) taskExecute(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

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

	result := data.Map{
		"retcode": -1,
		"stdout":  "",
		"stderr":  "",
	}

	ctx := task.Context()

	// Prepare command
	scmd.cmd = exec.CommandContext(ctx, "bash", "-c", scmd.runCmdString)
	scmd.cmd.SysProcAttr = getSyscallAttrs()

	// Set up the outputs (std and err)
	stdoutPipe, xerr := scmd.getStdoutPipe()
	if xerr != nil {
		return result, xerr
	}

	stderrPipe, xerr := scmd.getStderrPipe()
	if xerr != nil {
		return result, xerr
	}

	if !params.collectOutputs {
		if stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe); xerr != nil {
			return result, xerr
		}

		if stderrBridge, xerr = cli.NewStderrBridge(stderrPipe); xerr != nil {
			return result, xerr
		}

		if pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge); xerr != nil {
			return result, xerr
		}

		// Starts pipebridge if needed
		if xerr = pipeBridgeCtrl.Start(task); xerr != nil {
			return result, xerr
		}
	}

	// Launch the command and wait for its completion
	if xerr = scmd.Start(); xerr != nil {
		return result, xerr
	}

	if params.collectOutputs {
		if msgOut, err = ioutil.ReadAll(stdoutPipe); err != nil {
			return result, fail.ConvertError(err)
		}

		if msgErr, err = ioutil.ReadAll(stderrPipe); err != nil {
			return result, fail.ConvertError(err)
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
			return result, xerr
		} else if rc, ok = note.(int); ok && rc == -1 {
			if !params.collectOutputs {
				if derr := pipeBridgeCtrl.Stop(); derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
			return result, xerr
		}

		result["retcode"], ok = note.(int)
		if !ok {
			logrus.Warnf("Unable to recover 'retcode' because 'note' is not an integer: %v", note)
		}

		// Make sure all outputs have been processed
		if !params.collectOutputs {
			if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
				logrus.Error(pbcErr.Error())
			}

			if note, ok = xerr.Annotation("stderr"); ok {
				result["stderr"], ok = note.(string)
				if !ok {
					logrus.Warnf("Unable to recover 'stederr' because 'note' is not an string: %v", note)
				}
			}
		} else {
			result["stdout"] = string(msgOut)
			result["stderr"] = fmt.Sprint(string(msgErr), stderr)
		}
	} else {
		result["retcode"] = 0
		if params.collectOutputs {
			result["stdout"] = string(msgOut)
			result["stderr"] = string(msgErr)
		} else if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
			logrus.Error(pbcErr.Error())
		}
	}

	return result, nil
}

// Close is called to clean Command (close tunnel(s), remove temporary files, ...)
func (scmd *CliCommand) Close() fail.Error {
	var err1 error

	if len(scmd.tunnels) > 0 {
		err1 = scmd.tunnels.Close()
	}
	if err1 != nil {
		logrus.Errorf("Command.closeTunnels() failed: %s (%s)", err1.Error(), reflect.TypeOf(err1).String())
		defer func() { // lazy removal
			ierr := utils.LazyRemove(scmd.keyFile.Name())
			if ierr != nil {
				debug.IgnoreError(ierr)
			}
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
func createConsecutiveTunnels(sc ssh.Config, tunnels *Tunnels) (*Tunnel, fail.Error) {
	if sc != nil {
		// determine what gateway to use
		var gwConf ssh.Config

		gwConf, xerr := sc.GetPrimaryGatewayConfig()
		if xerr != nil {
			return nil, xerr
		}

		sgwConf, xerr := sc.GetSecondaryGatewayConfig()
		if xerr != nil {
			return nil, xerr
		}

		if gwConf != nil {
			gwi, _ := gwConf.GetIPAddress()
			gwp, _ := gwConf.GetPort()

			if !netutils.CheckRemoteTCP(gwi, int(gwp)) {
				if !valid.IsNil(sgwConf) {
					gwConf = sgwConf
					gwi, _ := sgwConf.GetIPAddress()
					gwp, _ := sgwConf.GetPort()
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
				gateway.IPAddress = ssh.LocalHost
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
		sshConfig.IPAddress = ssh.LocalHost
	}
	return tunnels, &sshConfig, nil
}

func createSSHCommand(
	sconf *Profile, cmdString, username, shell string, withTty, withSudo bool,
) (string, *os.File, fail.Error) {
	f, err := CreateTempFileFromString(sconf.PrivateKey, 0400)
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

	logrus.Debugf("Created SSH command '%s'", sshCmdString)

	return sshCmdString, f, nil
}

// NewCommand returns the cmd struct to execute runCmdString remotely
func (sconf *Profile) NewCommand(ctx context.Context, cmdString string) (ssh.CommandInterface, fail.Error) {
	return sconf.newCommand(ctx, cmdString, false, false)
}

// NewSudoCommand returns the cmd struct to execute runCmdString remotely. NewCommand is executed with sudo
func (sconf *Profile) NewSudoCommand(ctx context.Context, cmdString string) (ssh.CommandInterface, fail.Error) {
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

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to create SSH tunnel")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
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

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
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
	f, err := CreateTempFileFromString(sconf.PrivateKey, 0400)
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

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("ssh"), "('%s',%s)", phase, temporal.FormatDuration(timeout)).Entering().Exiting()
	defer fail.OnExitTraceError(
		&xerr, "timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, sconf.Hostname,
		temporal.FormatDuration(timeout),
	)

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

	cmdCloseFunc := func(cmd ssh.CommandInterface, deferErr *fail.Error) {
		derr := cmd.Close()
		if derr != nil {
			if deferErr != nil {
				if *deferErr != nil {
					*deferErr = fail.ConvertError(*deferErr)
					_ = (*deferErr).AddConsequence(derr)
				} else {
					*deferErr = derr
				}
			}
		}
	}

	retcode := -1
	iterations := 0
	begins := time.Now()
	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			iterations++

			// -- Try to see if 'phase' file exists... --
			sshCmd, innerXErr := sconf.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.%s.done", utils.VarFolder, phase))
			if innerXErr != nil {
				return innerXErr
			}

			// Do not forget to close command, ie close SSH tunnel
			defer func(cmd ssh.CommandInterface) { cmdCloseFunc(cmd, &innerXErr) }(sshCmd)

			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 { // nolint
				switch phase {
				case "final":
					// Before v21.05.0, final provisioning state is stored in user_data.phase2.done file, so try to see if legacy file exists...
					sshCmd, innerXErr = sconf.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.phase2.done", utils.VarFolder))
					if innerXErr != nil {
						return innerXErr
					}

					// Do not forget to close command, ie close SSH tunnel
					defer func(cmd ssh.CommandInterface) { cmdCloseFunc(cmd, &innerXErr) }(sshCmd)

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
		temporal.DefaultDelay(),
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

	logrus.Debugf(
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
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	sshCommand, xerr := sconf.newCopyCommand(ctx, localPath, remotePath, isUpload)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to create copy command")
	}

	// Do not forget to close sshCommand, allowing the SSH tunnel close and corresponding process cleanup
	defer func() {
		derr := sshCommand.Close()
		if derr != nil {
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
func (sconf *Profile) Enter(username, shell string) (ferr fail.Error) {
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
				logrus.Warnf("Error closing SSH tunnel: %v", nerr)
			}
		}
		if keyFile != nil {
			if nerr := utils.LazyRemove(keyFile.Name()); nerr != nil {
				logrus.Warnf("Error removing file %v", nerr)
			}
		}
		return fail.Wrap(xerr, "unable to create command")
	}

	defer func() {
		derr := utils.LazyRemove(keyFile.Name())
		if derr != nil {
			logrus.Warnf("Error removing temporary file: %v", derr)
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

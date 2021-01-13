/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package system

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
//      To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
//      use the same port for all access to a same host (not the case currently)
//      May not be used for interactive ssh connection...
const (
	sshOptions      = "-q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
	sshPingOptions  = "-q -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oChallengeResponseAuthentication=no" // VPL: Add "-o ConnectTimeout=<seconds>" to set a timeout
	sshCopyTemplate = `scp -i {{.IdentityFile}} -P {{.Port}} {{.Options}} {{if .IsUpload}}"{{.LocalPath}}" {{.User}}@{{.IPAddress}}:"{{.RemotePath}}"{{else}}{{.User}}@{{.IPAddress}}:"{{.RemotePath}}" "{{.LocalPath}}"{{end}}`
)

var (
	sshErrorMap = map[int]string{
		1:  "Malformed configuration or invalid cli options",
		2:  "Connection failed",
		65: "Host not allowed to connect",
		66: "General error in ssh protocol",
		67: "Key exchange failed",
		69: "MAC error",
		70: "Compression error",
		71: "Service not available",
		72: "Protocol version not supported",
		73: "Host key not verifiable",
		74: "Connection failed",
		75: "Disconnected by application",
		76: "Too many connections",
		77: "Authentication cancelled by user",
		78: "No more authentication methods available",
		79: "Invalid user name",
	}
	scpErrorMap = map[int]string{
		1:  "General error in file copy",
		2:  "Destination is not directory, but it should be",
		3:  "Maximum symlink level exceeded",
		4:  "Connecting to host failed",
		5:  "Connection broken",
		6:  "File does not exist",
		7:  "No permission to access file",
		8:  "General error in sftp protocol",
		9:  "File transfer protocol mismatch",
		10: "No file matches a given criteria",
		65: "Host not allowed to connect",
		66: "General error in ssh protocol",
		67: "Key exchange failed",
		69: "MAC error",
		70: "Compression error",
		71: "Service not available",
		72: "Protocol version not supported",
		73: "Host key not verifiable",
		74: "Connection failed",
		75: "Disconnected by application",
		76: "Too many connections",
		77: "Authentication cancelled by user",
		78: "No more authentication methods available",
		79: "Invalid user name",
	}
)

// IsSSHRetryable tells if the retcode of a ssh newCommand may be retried
func IsSSHRetryable(code int) bool {
	if code == 2 || code == 4 || code == 5 || code == 66 || code == 67 || code == 70 || code == 74 || code == 75 || code == 76 {
		return true
	}
	return false

}

// IsSCPRetryable tells if the retcode of a scp newCommand may be retried
func IsSCPRetryable(code int) bool {
	if code == 4 || code == 5 || code == 66 || code == 67 || code == 70 || code == 74 || code == 75 || code == 76 {
		return true
	}
	return false
}

// SSHConfig helper to manage ssh session
type SSHConfig struct {
	Hostname               string
	IPAddress              string
	Port                   int
	User                   string
	PrivateKey             string
	LocalPort              int
	GatewayConfig          *SSHConfig
	SecondaryGatewayConfig *SSHConfig
	// cmdTpl                 string
}

// IsNull tells if the instance is a null value
func (sconf *SSHConfig) IsNull() bool {
	return sconf == nil || sconf.IPAddress == ""
}

// SSHTunnel a SSH tunnel
type SSHTunnel struct {
	port      int
	cmd       *exec.Cmd
	cmdString string
	keyFile   *os.File
}

// SSHErrorString returns if possible the string corresponding to SSH execution
func SSHErrorString(retcode int) string {
	if msg, ok := sshErrorMap[retcode]; ok {
		return msg
	}
	return "Unqualified error"
}

// SCPErrorString returns if possible the string corresponding to SCP execution
func SCPErrorString(retcode int) string {
	if msg, ok := scpErrorMap[retcode]; ok {
		return msg
	}
	return "Unqualified error"
}

// Close closes ssh tunnel
func (stun *SSHTunnel) Close() fail.Error {
	defer func() {
		if lazyErr := utils.LazyRemove(stun.keyFile.Name()); lazyErr != nil {
			logrus.Error(lazyErr)
		}
	}()

	// Kills the process of the stun
	err := stun.cmd.Process.Kill()
	if err != nil {
		logrus.Errorf("stun.cmd.Process.Kill() failed: %s", reflect.TypeOf(err).String())
		return fail.Wrap(err, "unable to close stun")
	}
	// Kills remaining processes if there are some
	bytesCmd, err := exec.Command("pgrep", "-f", stun.cmdString).Output()
	if err == nil {
		portStr := strings.Trim(string(bytesCmd), "\n")
		if _, err = strconv.Atoi(portStr); err == nil {
			if err = exec.Command("kill", "-9", portStr).Run(); err != nil {
				logrus.Errorf("kill -9 failed: %s", reflect.TypeOf(err).String())
				return fail.Wrap(err, "unable to close stun")
			}
		}
	}
	return nil
}

// GetFreePort get a free port
func getFreePort() (int, fail.Error) {
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
	return port, nil
}

// CreateTempFileFromString creates a temporary file containing 'content'
func CreateTempFileFromString(content string, filemode os.FileMode) (*os.File, fail.Error) {
	defaultTmpDir := "/tmp"
	if runtime.GOOS == "windows" {
		defaultTmpDir = ""
	}

	f, err := ioutil.TempFile(defaultTmpDir, "") // TODO: Windows friendly
	if err != nil {
		return nil, fail.ExecutionError(err, "failed to create temporary file")
	}
	_, err = f.WriteString(content)
	if err != nil {
		logrus.Warnf("Error writing string: %v", err)
		return nil, fail.ExecutionError(err, "failed to wrote string to temporary file")
	}

	err = f.Chmod(filemode)
	if err != nil {
		logrus.Warnf("Error changing directory: %v", err)
		return nil, fail.ExecutionError(err, "failed to change temporary file acess rights")
	}

	err = f.Close()
	if err != nil {
		logrus.Warnf("Error closing file: %v", err)
		return nil, fail.ExecutionError(err, "failed to close temporary file")
	}

	return f, nil
}

func isTunnelReady(port int) bool {
	// Try to create a server with the port
	server, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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
// if localPort is set to 0 then it's  automatically choosed
func buildTunnel(scfg *SSHConfig) (*SSHTunnel, fail.Error) {
	f, err := CreateTempFileFromString(scfg.GatewayConfig.PrivateKey, 0400)
	if err != nil {
		return nil, err
	}
	localPort := scfg.LocalPort
	if localPort == 0 {
		localPort, err = getFreePort()
		if err != nil {
			return nil, err
		}
	}

	// TODO: add "ssh ping" before this code ?
	options := sshOptions + " -oServerAliveInterval=60"
	cmdString := fmt.Sprintf("ssh -i %s -NL 127.0.0.1:%d:%s:%d %s@%s %s -p %d",
		f.Name(),
		localPort,
		scfg.IPAddress,
		scfg.Port,
		scfg.GatewayConfig.User,
		scfg.GatewayConfig.IPAddress,
		options,
		scfg.GatewayConfig.Port)
	cmd := exec.Command("sh", "-c", cmdString)
	cerr := cmd.Start()
	//	err = cmd.Wait()
	if cerr != nil {
		return nil, fail.ToError(cerr)
	}

	/*
		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			if runCmdString != "" {
				logrus.Debugf("[TRACE] %s", runCmdString)
			}
			_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", scfg.IPAddress)), 0777)
			partials := strings.Split(f.Name(), "/")
			dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/%s.sshkey", scfg.IPAddress, partials[len(partials)-1]))
			err = ioutil.WriteFile(dumpName, []byte(scfg.GatewayConfig.PrivateKey), 0644)
			if err != nil {
				logrus.Warnf("[TRACE] Failure storing key in %s", dumpName)
			}
		}
	*/

	for nbiter := 0; !isTunnelReady(localPort) && nbiter < 100; nbiter++ {
		time.Sleep(10 * time.Millisecond)
	}
	return &SSHTunnel{
		port:      localPort,
		cmd:       cmd,
		cmdString: cmdString,
		keyFile:   f,
	}, nil
}

// SSHCommand defines a SSH newCommand
type SSHCommand struct {
	runCmdString  string
	pingCmdString string
	cmd           *exec.Cmd
	tunnels       []*SSHTunnel
	keyFile       *os.File
}

func (scmd *SSHCommand) closeTunneling() fail.Error {
	var err fail.Error
	for _, t := range scmd.tunnels {
		err = t.Close()
	}
	scmd.tunnels = []*SSHTunnel{}

	// Tunnels are imbricated only last error is significant
	if err != nil {
		logrus.Errorf("closeTunneling: %s", reflect.TypeOf(err).String())
	}

	return err
}

// Wait waits for the newCommand to exit and waits for any copying to stdin or copying from stdout or stderr to complete.
// The newCommand must have been started by Start.
// The returned error is nil if the newCommand runs, has no problems copying stdin, stdout, and stderr, and exits with a zero exit status.
// If the newCommand fails to run or doesn't complete successfully, the error is of type *ExitError. Other error types may be returned for I/O problems.
// Wait also waits for the I/O loop copying from c.Stdin into the process's standard input to complete.
// Wait releases any resources associated with the cmd.
// !!!ATTENTION!!!: the error returned is NOT USING fail.Error because we may NEED TO CAST the error to recover return code
func (scmd *SSHCommand) Wait() error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}

	return scmd.cmd.Wait()
}

// Kill kills SSHCommand process and releases any resources associated with the SSHCommand.
func (scmd *SSHCommand) Kill() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}

	if err := scmd.cmd.Process.Kill(); err != nil {
		return fail.ToError(err)
	}
	return nil
}

// getStdoutPipe returns a pipe that will be connected to the newCommand's standard output when the newCommand starts.
// Wait will close the pipe after seeing the newCommand exit, so most callers need not close the pipe themselves; however, an implication is that it is incorrect to call Wait before all reads from the pipe have completed.
// For the same reason, it is incorrect to call Run when using getStdoutPipe.
func (scmd *SSHCommand) getStdoutPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdoutPipe()
	if err != nil {
		return nil, fail.ToError(err)
	}
	return pipe, nil
}

// getStderrPipe returns a pipe that will be connected to the newCommand's standard error when the newCommand starts.
// Wait will close the pipe after seeing the newCommand exit, so most callers need not close the pipe themselves; however, an implication is that it is incorrect to call Wait before all reads from the pipe have completed. For the same reason, it is incorrect to use Run when using getStderrPipe.
func (scmd *SSHCommand) getStderrPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StderrPipe()
	if err != nil {
		return nil, fail.ToError(err)
	}
	return pipe, nil
}

// getStdinPipe returns a pipe that will be connected to the newCommand's standard input when the newCommand starts.
// The pipe will be closed automatically after Wait sees the newCommand exit.
// A caller need only call Close to force the pipe to close sooner.
// For example, if the newCommand being run will not exit until standard input is closed, the caller must close the pipe.
func (scmd *SSHCommand) getStdinPipe() (io.WriteCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdinPipe()
	if err != nil {
		return nil, fail.ToError(err)
	}
	return pipe, nil
}

// Output returns the standard output of newCommand started.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (scmd *SSHCommand) Output() ([]byte, fail.Error) {
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

// CombinedOutput returns the combined standard of newCommand started
// output and standard error.
func (scmd *SSHCommand) CombinedOutput() ([]byte, fail.Error) {
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

// Start starts the specified newCommand but does not wait for it to complete.
// The Wait method will return the exit code and release associated resources
// once the newCommand exits.
func (scmd *SSHCommand) Start() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	if err := scmd.cmd.Start(); err != nil {
		return fail.ToError(err)
	}
	return nil
}

// // Display ...
// func (sc *SSHCommand) Display() string {
// 	if sc == nil {
// 		return ""
// 	}
//
// 	return sc.runCmdString
// }

// Run starts the specified newCommand and waits for it to complete.
//
// The returned error is nil if the newCommand runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
//
// If the newCommand starts but does not complete successfully, the error is of
// type *ExitError. Other error types may be returned for other situations.
//
// WARNING : This function CAN lock, use .RunWithTimeout instead
func (scmd *SSHCommand) Run(task concurrency.Task, outs outputs.Enum) (int, string, string, fail.Error) {
	if scmd == nil {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return -1, "", "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s)", outs.String()).WithStopwatch().Entering()
	defer tracer.Exiting()

	return scmd.RunWithTimeout(task, outs, 0)
}

// RunWithTimeout ...
func (scmd *SSHCommand) RunWithTimeout(task concurrency.Task, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	if scmd == nil {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return -1, "", "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("command=\n%s\n", sc.runCmdString)
	defer tracer.Exiting()

	// // Prepare newCommand
	// ctx, xerr := task.GetContext()
	// if xerr != nil {
	// 	return -1, "", "", xerr
	// }
	// scmd.cmd = exec.NewCommandWithContext(ctx, "bash", "-c", scmd.runCmdString)
	//
	// // Set up the outputs (std and err)
	// stdoutPipe, xerr := scmd.getStdoutPipe()
	// if xerr != nil {
	// 	return -1, "", "", xerr
	// }
	//
	// stderrPipe, xerr := scmd.getStderrPipe()
	// if xerr != nil {
	// 	return -1, "", "", xerr
	// }

	subtask, xerr := concurrency.NewTaskWithParent(task)
	if xerr != nil {
		return -1, "", "", xerr
	}

	if _, xerr = subtask.StartWithTimeout(scmd.taskExecute, taskExecuteParameters{/*stdout: stdoutPipe, stderr: stderrPipe, */ collectOutputs: outs != outputs.DISPLAY}, timeout); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			xerr = fail.Wrap(xerr.Cause(), "reached timeout of %s", temporal.FormatDuration(timeout))
		}
		return -1, "", "", xerr
	}

	r, xerr := subtask.Wait()
	if xerr != nil {
		return -1, "", "", xerr
	}

	if result, ok := r.(data.Map); ok {
		return result["retcode"].(int), result["stdout"].(string), result["stderr"].(string), nil
	}
	return -1, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")
}

type taskExecuteParameters struct {
	// stdout, stderr io.ReadCloser
	collectOutputs bool
}

func (scmd *SSHCommand) taskExecute(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	params, ok := p.(taskExecuteParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'taskExecuteParameters'")
	}
	// if params.stdout == nil {
	// 	return nil, fail.InvalidParameterError("p.stdout", "cannot be nil")
	// }
	// if params.stderr == nil {
	// 	return nil, fail.InvalidParameterError("p.stderr", "cannot be nil")
	// }

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

	ctx, xerr := task.GetContext()
	if xerr != nil {
		return result, xerr
	}

	// Check SSH is responding on remote side
	bash, err := exec.LookPath("bash")
	if err != nil {
		return nil, fail.Wrap(err, "failed to find bash binary")
	}
	proc := exec.Command(bash, "-c", scmd.pingCmdString)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	err = proc.Run()
	if err != nil {
		return nil, fail.Wrap(fail.ExecutionError(err), "failed to check if remote SSH is available")
	}

	// Prepare newCommand
	scmd.cmd = exec.CommandContext(ctx, "bash", "-c", scmd.runCmdString)

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
		if stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe /*params.stdout*/); xerr != nil {
			return result, xerr
		}

		if stderrBridge, xerr = cli.NewStderrBridge(stderrPipe /*params.stderr*/); xerr != nil {
			return result, xerr
		}

		if pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge); xerr != nil {
			return result, xerr
		}
	}

	// Starts pipebridge if needed
	if !params.collectOutputs {
		if xerr = pipeBridgeCtrl.Start(task); xerr != nil {
			return result, xerr
		}
	}

	// Launch the newCommand and wait for its completion
	if xerr = scmd.Start(); xerr != nil {
		return result, xerr
	}

	if params.collectOutputs {
		if msgOut, err = ioutil.ReadAll(stdoutPipe /*params.stdout*/); err != nil {
			return result, fail.ToError(err)
		}

		if msgErr, err = ioutil.ReadAll(stderrPipe /*params.stderr*/); err != nil {
			return result, fail.ToError(err)
		}
	}

	var pbcErr error
	runErr := scmd.Wait()
	_ = stdoutPipe.Close() /*params.stdout.Close()*/
	_ = stderrPipe.Close() /*params.stderr.Close()*/

	if runErr == nil {
		result["retcode"] = 0
		if params.collectOutputs {
			result["stdout"] = string(msgOut)
			result["stderr"] = string(msgErr)
		} else {
			if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
				logrus.Error(pbcErr.Error())
			}

		}
	} else {
		xerr = fail.ExecutionError(runErr)
		// If error doesn't contain ouputs and return code of the process, stop the pipe bridges and return error
		var (
			note   data.Annotation
			stderr string
			ok     bool
		)
		if note, ok = xerr.Annotation("retcode"); !ok || note.(int) == -1 {
			if !params.collectOutputs {
				if derr := pipeBridgeCtrl.Stop(); derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
			return result, xerr
		}
		result["retcode"] = note.(int)

		// Make sure all outputs have been processed
		if !params.collectOutputs {
			if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
				logrus.Error(pbcErr.Error())
			}

			if note, ok = xerr.Annotation("stderr"); ok {
				result["stderr"] = note.(string)
			}
		} else {
			result["stdout"] = string(msgOut)
			result["stderr"] = fmt.Sprint(string(msgErr), stderr)
		}
	}

	return result, nil
}

// Close is called to clean SSHCommand (close tunnel(s), remove temporary files, ...)
func (scmd *SSHCommand) Close() fail.Error {
	err1 := scmd.closeTunneling()
	err2 := utils.LazyRemove(scmd.keyFile.Name())
	if err1 != nil {
		logrus.Errorf("closeTunneling() failed: %s\n", reflect.TypeOf(err1).String())
		return fail.Wrap(err1, "unable to close SSH tunnels")
	}
	if err2 != nil {
		return fail.Wrap(err2, "unable to close SSH tunnels")
	}
	return nil
}

func recCreateTunnels(sc *SSHConfig, tunnels *[]*SSHTunnel) (*SSHTunnel, fail.Error) {
	if sc != nil {
		tunnel, err := recCreateTunnels(sc.GatewayConfig, tunnels)
		if err != nil {
			return nil, err
		}
		cfg := sc
		if tunnel != nil {
			gateway := *sc.GatewayConfig
			gateway.Port = tunnel.port
			gateway.IPAddress = "127.0.0.1"
			cfg.GatewayConfig = &gateway
		}
		if cfg.GatewayConfig != nil {
			tunnel, err = buildTunnel(cfg)
			if err != nil {
				return nil, err
			}
			*tunnels = append(*tunnels, tunnel)
			return tunnel, err
		}
	}
	return nil, nil
}

// CreateTunneling ...
func (sconf *SSHConfig) CreateTunneling() ([]*SSHTunnel, *SSHConfig, fail.Error) {
	var tunnels []*SSHTunnel
	tunnel, err := recCreateTunnels(sconf, &tunnels)
	if err != nil {
		return nil, nil, fail.Wrap(err, "unable to create SSH Tunnels")
	}
	sshConfig := *sconf
	if tunnel == nil {
		return nil, &sshConfig, nil
	}

	if sconf.GatewayConfig != nil {
		sshConfig.Port = tunnel.port
		sshConfig.IPAddress = "127.0.0.1"
	}
	return tunnels, &sshConfig, nil
}

func createSSHCommands(sconf *SSHConfig, cmdString, username, shell string, withTty, withSudo bool) (string, string, *os.File, fail.Error) {
	f, err := CreateTempFileFromString(sconf.PrivateKey, 0400)
	if err != nil {
		return "", "", nil, fail.Wrap(err, "unable to create temporary key file")
	}

	options := sshOptions + " -oLogLevel=error"

	sshCmdString := fmt.Sprintf("ssh -i %s %s -p %d %s@%s", f.Name(), options, sconf.Port, sconf.User, sconf.IPAddress)
	sshPingCmdString := fmt.Sprintf("ssh -i %s %s -oConnectTimeout=5 -p %d %s@%s exit", f.Name(), sshPingOptions, sconf.Port, sconf.User, sconf.IPAddress)

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
		//	 su may be used to ask password then launch a newCommand but it launches a shell without tty (sudo for example would refuse to work)
		cmd = "su " + username + " -c exit && " + sshCmdString + " -t sudo -u " + username
		withTty = true
	}

	if withTty {
		// tty option is required for some newCommand like ls
		sshCmdString += " -t"
	}

	if withSudo {
		if cmd == "" {
			// tty option is required for some newCommand like ls
			cmd = "sudo"
		}
	}

	if cmd != "" {
		sshCmdString += " " + cmd + " " + shell
	}

	if cmdString != "" {
		sshCmdString += fmt.Sprintf(" <<'ENDSSH'\n%s\nENDSSH", cmdString)
	}
	//logrus.Debugf("createSSHCommands() sshCmdString: %s\n", sshCmdString)

	return sshCmdString, sshPingCmdString, f, nil

}

// NewCommand returns the cmd struct to execute runCmdString remotely
func (sconf *SSHConfig) NewCommand(task concurrency.Task, cmdString string) (*SSHCommand, fail.Error) {
	return sconf.newCommand(task, cmdString, false, false)
}

// NewSudoCommand returns the cmd struct to execute runCmdString remotely. NewCommand is executed with sudo
func (sconf *SSHConfig) NewSudoCommand(task concurrency.Task, cmdString string) (*SSHCommand, fail.Error) {
	return sconf.newCommand(task, cmdString, false, true)
}

func (sconf *SSHConfig) newCommand(task concurrency.Task, cmdString string, withTty, withSudo bool) (*SSHCommand, fail.Error) {
	if sconf == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if cmdString = strings.TrimSpace(cmdString); cmdString == "" {
		return nil, fail.InvalidParameterError("runCmdString", "cannot be empty string")
	}

	// ctx, xerr := task.GetContext()
	// if xerr != nil {
	// 	return nil, xerr
	// }

	tunnels, sshConfig, err := sconf.CreateTunneling()
	if err != nil {
		return nil, fail.Wrap(err, "unable to create newCommand")
	}

	sshCmdString, sshPingCmdString, keyFile, err := createSSHCommands(sshConfig, cmdString, "", "", withTty, withSudo)
	if err != nil {
		return nil, fail.Wrap(err, "unable to create newCommand")
	}

	// cmd := exec.NewCommandWithContext(ctx, "bash", "-c", sshCmdString)
	sshCommand := SSHCommand{
		runCmdString:  sshCmdString,
		pingCmdString: sshPingCmdString,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return &sshCommand, nil
}

// WaitServerReady waits until the SSH server is ready
func (sconf *SSHConfig) WaitServerReady(task concurrency.Task, phase string, timeout time.Duration) (out string, xerr fail.Error) {
	if sconf == nil {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sconf.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sconf.IPAddress", "cannot be empty string")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("sconf"), "('%s',%s)", phase, temporal.FormatDuration(timeout)).Entering().Exiting()
	defer fail.OnExitTraceError(&xerr, "timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, sconf.Hostname, temporal.FormatDuration(timeout))

	originalPhase := phase
	if phase == "ready" {
		phase = "final"
	}

	var (
		retcode        int
		stdout, stderr string
	)

	begins := time.Now()
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			taskStatus, _ := task.GetStatus()
			if taskStatus == concurrency.ABORTED {
				return retry.StopRetryError(nil, "operation aborted")
			}

			sshCmd, innerErr := sconf.NewCommand(task, fmt.Sprintf("sudo cat /opt/safescale/var/state/user_data.%s.done", phase))
			if innerErr != nil {
				return innerErr
			}

			defer func() { _ = sshCmd.Close() }()

			var innerXErr fail.Error
			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(task, outputs.COLLECT, timeout)
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				if retcode == 255 {
					return fail.NewError("remote SSH not ready: error code: 255; Output [%s]; Error [%s]", stdout, stderr)
				}
				return fail.NewError("remote SSH NOT ready: error code: %d; Output [%s]; Error [%s]", retcode, stdout, stderr)
			}
			return nil
		},
		timeout*2,
	)
	if retryErr != nil {
		return stdout, retryErr
	}

	logrus.Debugf("host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.Hostname, originalPhase, temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// Copy copies a file/directory from/to local to/from remote
func (sconf *SSHConfig) Copy(task concurrency.Task, remotePath, localPath string, isUpload bool) (errc int, stdout string, stderr string, err fail.Error) {
	return sconf.copy(task, remotePath, localPath, isUpload, 0)
}

// CopyWithTimeout copies a file/directory from/to local to/from remote, and fails after 'timeout'
func (sconf *SSHConfig) CopyWithTimeout(
	task concurrency.Task, remotePath, localPath string, isUpload bool, timeout time.Duration,
) (int, string, string, fail.Error) {

	return sconf.copy(task, remotePath, localPath, isUpload, timeout)
}


// copy copies a file/directory from/to local to/from remote, and fails after 'timeout' (if timeout > 0)
func (sconf *SSHConfig) copy(
	task concurrency.Task,
	remotePath, localPath string,
	isUpload bool,
	timeout time.Duration,
) (retcode int, stdout string, stderr string, xerr fail.Error) {

	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return 0, "", "", fail.Wrap(xerr, "unable to create tunnels")
	}

	identityfile, xerr := CreateTempFileFromString(sshConfig.PrivateKey, 0400)
	if xerr != nil {
		return 0, "", "", fail.Wrap(xerr, "unable to create temporary key file")
	}

	cmdTemplate, err := template.New("NewCommand").Parse(sshCopyTemplate)
	if err != nil {
		return 0, "", "", fail.Wrap(err, "error parsing newCommand template")
	}

	options := sshOptions + " -oLogLevel=error"
	var copyCommand bytes.Buffer
	err = cmdTemplate.Execute(&copyCommand, struct {
		IdentityFile string
		Port         int
		Options      string
		User         string
		IPAddress    string
		RemotePath   string
		LocalPath    string
		IsUpload     bool
	}{
		IdentityFile: identityfile.Name(),
		Port:         sshConfig.Port,
		Options:      options,
		User:         sshConfig.User,
		IPAddress:    sshConfig.IPAddress,
		RemotePath:   remotePath,
		LocalPath:    localPath,
		IsUpload:     isUpload,
	})
	if err != nil {
		return 0, "", "", fail.Wrap(err, "error executing template")
	}

	sshCmdString := copyCommand.String()
	// cmd := exec.NewCommand("bash", "-c", sshCmdString)
	sshCommand := SSHCommand{
		// cmd:     cmd,
		runCmdString: sshCmdString,
		tunnels:      tunnels,
		keyFile:      identityfile,
	}

	return sshCommand.RunWithTimeout(task, outputs.COLLECT, timeout)
}

// Enter Enter to interactive shell
func (sconf *SSHConfig) Enter(username, shell string) (xerr fail.Error) {
	tunnels, sshConfig, xerr := sconf.CreateTunneling()
	if xerr != nil {
		for _, t := range tunnels {
			nerr := t.Close()
			if nerr != nil {
				logrus.Warnf("Error closing sconf tunnel: %v", nerr)
			}
		}
		return fail.Wrap(xerr, "unable to create newCommand")
	}

	sshCmdString, sshPingCmdString, keyFile, xerr := createSSHCommands(sshConfig, "", username, shell, true, false)
	if xerr != nil {
		for _, t := range tunnels {
			nerr := t.Close()
			if nerr != nil {
				logrus.Warnf("Error closing sconf tunnel: %v", nerr)
			}
		}
		if keyFile != nil {
			nerr := utils.LazyRemove(keyFile.Name())
			if nerr != nil {
				logrus.Warnf("Error removing file %v", nerr)
			}
		}
		return fail.Wrap(xerr, "unable to create newCommand")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		for _, t := range tunnels {
			nerr := t.Close()
			if nerr != nil {
				logrus.Warnf("Error closing sconf tunnel: %v", nerr)
			}
		}
		if keyFile != nil {
			nerr := utils.LazyRemove(keyFile.Name())
			if nerr != nil {
				logrus.Warnf("Error removing file %v", nerr)
			}
		}
		return fail.Wrap(err, "unable to create newCommand")
	}

	// First check sconf is available
	proc := exec.Command(bash, "-c", sshPingCmdString)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	err = proc.Run()
	if err != nil {
		nerr := utils.LazyRemove(keyFile.Name())
		if nerr != nil {
			logrus.Warnf("Error removing temporary file: %v", nerr)
		}

		return fail.Wrap(fail.ExecutionError(err), "failed to check if remote SSH is available")
	}

	// .. if yes, execute real newCommand
	proc = exec.Command(bash, "-c", sshCmdString)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	err = proc.Run()

	nerr := utils.LazyRemove(keyFile.Name())
	if nerr != nil {
		logrus.Warnf("Error removing file temporary %v", nerr)
	}

	if err != nil {
		return fail.ExecutionError(err)
	}
	return nil
}

// // NewCommandWithContext is like NewCommand but includes a context.
// //
// // The provided context is used to kill the process (by calling
// // os.Process.Kill) if the context becomes done before the newCommand
// // completes on its own.
// func (ssh *SSHConfig) NewCommandWithContext(ctx context.Context, runCmdString string) (*SSHCommand, error) {
// 	tunnels, sshConfig, err := ssh.CreateTunneling()
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to create newCommand : %s", err.Error()
// 	}
// 	sshCmdString, sshPingCmdString, keyFile, err := createSSHCommands(sshConfig, runCmdString, false)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to create newCommand : %s", err.Error()
// 	}
//
// 	cmd := exec.CommandContext(ctx, "bash", "-c", sshCmdString)
// 	sshCommand := SSHCommand{
// 		cmd:     cmd,
// 		tunnels: tunnels,
// 		keyFile: keyFile,
// 	}
// 	return &sshCommand, nil
// }

// // CreateKeyPair creates a key pair
// func CreateKeyPair() (publicKeyBytes []byte, privateKeyBytes []byte, xerr fail.Error) {
// 	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
// 	publicKey := privateKey.PublicKey
// 	pub, err := ssh.NewPublicKey(&publicKey)
// 	if err != nil {
// 		return nil, nil, fail.ToError(err)
// 	}
//
// 	publicKeyBytes = ssh.MarshalAuthorizedKey(pub)
//
// 	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
// 	privateKeyBytes = pem.EncodeToMemory(
// 		&pem.Block{
// 			Type:  "RSA PRIVATE KEY",
// 			Bytes: priBytes,
// 		},
// 	)
// 	return publicKeyBytes, privateKeyBytes, nil
// }

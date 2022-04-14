//go:build tunnel
// +build tunnel

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

package system

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/system/sshtunnel"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"

	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
	"github.com/pkg/sftp"
)

// SSHConfig helper to manage ssh session
type SSHConfig struct {
	User                   string
	IPAddress              string
	PrivateKey             string
	Port                   int
	LocalPort              int
	LocalHost              string
	GatewayConfig          *SSHConfig
	SecondaryGatewayConfig *SSHConfig
	Hostname               string
}

// SSHTunnel a SSH tunnel
type SSHTunnel struct {
	cfg  SSHConfig // nolint
	port int       // nolint
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

	return f, nil
}

// SSHCommand defines a SSH command
type SSHCommand struct {
	withSudo bool
	username string
	cfg      *SSHConfig
	cmd      *exec.Cmd
	tunnels  *sshtunnel.SSHTunnel
}

func (sc *SSHCommand) closeTunneling() error {
	logrus.Debugf("Closing tunnels")

	if sc.tunnels != nil {
		sc.tunnels.Close()
	}

	return nil
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (sc *SSHCommand) Output() (_ []byte, ferr error) {
	if sc.cmd.Stdout != nil {
		return []byte(""), nil
	}

	defer func() {
		nerr := sc.cleanup()
		if nerr != nil {
			logrus.Warnf("Error waiting for command cleanup: %v", nerr)
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
func (sc *SSHCommand) Display() string {
	return strings.Join(sc.cmd.Args, " ")
}

// RunWithTimeout ...
func (sc *SSHCommand) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	var rc int
	var rout string
	var rerr string
	var pb fail.Error

	xerr := retry.WhileUnsuccessful(func() error { // retry only if we have a tunnel problem
		tu, _, err := sc.cfg.CreateTunneling()
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
		time.Second,
		timeout+5*time.Second) // no need to increase this, if there is a tunnel problem, it happens really fast

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
func (sc *SSHCommand) NewRunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, "", "", xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("command=\n%s\n", sc.Display())
	defer tracer.Exiting()

	if task != nil && task.Aborted() {
		return 0, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")
	}

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
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		logrus.Debugf("Dialing to %s:%d using %s:%d", sc.cfg.LocalHost, sc.cfg.LocalPort, "localhost", sc.tunnels.GetLocalEndpoint().Port())
		client, err := sshtunnel.DialSSHWithTimeout("tcp", fmt.Sprintf("%s:%d", sc.cfg.LocalHost, sc.tunnels.GetLocalEndpoint().Port()), directConfig, 45*time.Second)
		if err != nil {
			if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
				logrus.Debugf(spew.Sdump(err))
			}
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() || ne.Temporary() {
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

		if task != nil && task.Aborted() {
			results <- result{-1, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")}
			return
		}

		beginDial := time.Now()
		retries := 0
		eofCount := 0

		var session *ssh.Session

		err = retry.WhileUnsuccessful(func() error { // FIXME: Turn this into goroutine
			// Each ClientConn can support multiple interactive sessions,
			// represented by a Session.
			var internalErr error
			var newsession *ssh.Session
			newsession, internalErr = client.NewSession()
			if internalErr != nil {
				retries = retries + 1 // nolint
				logrus.Tracef("problem creating session: %s", internalErr.Error())
				if strings.Contains(internalErr.Error(), "EOF") {
					eofCount = eofCount + 1
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
			logrus.Debugf("creating the session took %s and %d retries", time.Since(beginDial), retries)
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

		if task != nil && task.Aborted() {
			results <- result{-1, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")}
			return
		}

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
				logrus.Debugf("Error running command after %s: %s", time.Since(beginIter), err.Error())
				errorCode = -1

				if ee, ok := err.(*ssh.ExitError); ok {
					errorCode = ee.ExitStatus()
					logrus.Debugf("Found an exit error of command '%s': %d", sc.cmd.String(), errorCode)
				}

				if _, ok := err.(*ssh.ExitMissingError); ok {
					logrus.Warnf("Found exit missing error of command '%s'", sc.cmd.String())
					errorCode = -2
				}

				if _, ok := err.(net.Error); ok {
					logrus.Debugf("Found network error running command '%s'", sc.cmd.String())
					errorCode = 255
				}

				results <- result{
					errorcode: errorCode,
					stdout:    "",
					stderr:    "",
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
			}
			return res.errorcode, res.stdout, res.stderr, nil
		case <-enough:
			return 255, "", "", fail.NewError("received timeout of %s", timeout)
		}
	}

	res := <-results

	if outs == outputs.DISPLAY {
		fmt.Print(res.stdout)
	}

	return res.errorcode, res.stdout, res.stderr, nil
}

func (sc *SSHCommand) cleanup() error {
	err1 := sc.closeTunneling()
	if err1 != nil {
		logrus.Errorf("closeTunneling() failed: %s\n", reflect.TypeOf(err1).String())
		return fmt.Errorf("unable to close SSH tunnels: %s", err1.Error())
	}

	return nil
}

// Close this function exists only to provide compatibility with previous SSH api
func (sc *SSHCommand) Close() fail.Error {
	return nil
}

// CreateTunneling ...
func (sc *SSHConfig) CreateTunneling() (*sshtunnel.SSHTunnel, *SSHConfig, error) {
	var tu *sshtunnel.SSHTunnel

	if sc.LocalHost == "" {
		sc.LocalHost = "127.0.0.1" // TODO Remove hardcoded string
	}

	internalPort := 22 // all machines use port 22... // TODO Remove magic number
	var gateway *sshtunnel.Endpoint
	if sc.GatewayConfig == nil { // it has to be a gateway
		internalPort = sc.Port // ... except maybe the gateway itself

		var rerr error
		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", sc.User, sc.IPAddress, sc.Port),
			sshtunnel.EndpointOptionKeyFromString(sc.PrivateKey, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	} else {
		var rerr error
		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", sc.GatewayConfig.User, sc.GatewayConfig.IPAddress, sc.GatewayConfig.Port),
			sshtunnel.EndpointOptionKeyFromString(sc.GatewayConfig.PrivateKey, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	}

	server, err := sshtunnel.NewEndpoint(fmt.Sprintf("%s:%d", sc.IPAddress, internalPort),
		sshtunnel.EndpointOptionKeyFromString(sc.PrivateKey, ""))
	if err != nil {
		return nil, nil, err
	}
	local, err := sshtunnel.NewEndpoint(fmt.Sprintf("localhost:%d", sc.LocalPort))
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

	var tsErr error
	go func() {
		tsErr = tu.Start()
		if tsErr != nil {
			tu.Close()
		}
	}()

	tunnelReady := <-tu.Ready()
	if !tunnelReady {
		return nil, nil, fmt.Errorf("unable to establish tunnel: %w", tsErr)
	}

	return tu, sc, nil
}

// Command returns the cmd struct to execute cmdString remotely
func (sc *SSHConfig) Command(cmdString string) (*SSHCommand, fail.Error) {
	return sc.command(cmdString, false, false)
}

// NewCommand returns the cmd struct to execute cmdString remotely
func (sc *SSHConfig) NewCommand(_ context.Context, cmdString string) (*SSHCommand, fail.Error) {
	return sc.command(cmdString, false, false)
}

// SudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sc *SSHConfig) SudoCommand(cmdString string) (*SSHCommand, fail.Error) {
	return sc.command(cmdString, false, true)
}

// NewSudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sc *SSHConfig) NewSudoCommand(_ context.Context, cmdString string) (*SSHCommand, fail.Error) {
	return sc.command(cmdString, false, true)
}

func (sc *SSHConfig) command(cmdString string, withTty, withSudo bool) (*SSHCommand, fail.Error) {
	cmd := exec.Command(cmdString)
	sshCommand := SSHCommand{
		withSudo: withSudo,
		username: "",
		cfg:      sc,
		cmd:      cmd,
	}
	return &sshCommand, nil
}

// WaitServerReady waits until the SSH server is ready
// the 'timeout' parameter is in minutes
func (sc *SSHConfig) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, err fail.Error) {
	if sc == nil {
		return "", fail.InvalidInstanceError()
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sc.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sc.Host", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %s)", phase, temporal.FormatDuration(timeout)).WithStopwatch().Entering()
	defer tracer.Exiting()

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
			iterations++

			// FIXME: Remove WaitServerReady logs and ensure minimum of iterations
			if task != nil {
				if task != nil && task.Aborted() {
					return fail.AbortedError(nil, "task already aborted by the parent")
				}
			}

			cmd, _ := sc.Command(fmt.Sprintf("sudo cat %s/user_data.%s.done", utils.StateFolder, phase))

			var xerr fail.Error
			retcode, stdout, stderr, xerr = cmd.RunWithTimeout(task.Context(), outputs.COLLECT, 20*time.Second) // FIXME: Remove hardcoded timeout
			if xerr != nil {
				return xerr
			}

			if retcode != 0 {
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
		temporal.DefaultDelay(),
		timeout+time.Minute,
	)
	if retryErr != nil {
		logrus.Debugf("WaitServerReady: the wait finished with: %v", retryErr)
		return stdout, retryErr
	}

	if !strings.HasPrefix(stdout, "0,") {
		return stdout, fail.NewError("PROVISIONING ERROR: host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sc.IPAddress, originalPhase,
			temporal.FormatDuration(time.Since(begins)), stdout)
	}

	logrus.Debugf(
		"host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sc.IPAddress, originalPhase,
		temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// CopyWithTimeout ...
func (sc *SSHConfig) CopyWithTimeout(ctx context.Context, remotePath string, localPath string, isUpload bool, timeout time.Duration) (int, string, string, fail.Error) {
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

	rCh := make(chan result)
	go func() {
		defer close(rCh)

		ac, ao, ae, err := sc.Copy(currentCtx, remotePath, localPath, isUpload)
		rCh <- result{
			code:   ac,
			stdout: ao,
			stderr: ae,
			err:    err,
		}
	}()

	select {
	case res := <-rCh: // if it works return the return
		return res.code, res.stderr, res.stderr, fail.Wrap(res.err)
	case <-ctx.Done(): // if not because parent context was canceled
	case <-currentCtx.Done(): // or timeout hits
	}

	// wait anyway until call it's finished, then return an error
	// if sc.Copy can handle contexts well, we don't have to wait until it's finished
	// however is not the case here
	<-rCh
	if ctx.Err() != nil {
		return -1, "", "", fail.Wrap(ctx.Err())
	}
	if currentCtx.Err() != nil {
		return -1, "", "", fail.Wrap(currentCtx.Err())
	}
	return -1, "", "", fail.NewError("timeout copying...")
}

// Copy copies a file/directory from/to local to/from remote
func (sc *SSHConfig) Copy(ctx context.Context, remotePath string, localPath string, isUpload bool) (int, string, string, fail.Error) {
	// FIXME: Use ctx if it can be handled at lower levels, if not, remove it as a parameter

	tu, sshConfig, err := sc.CreateTunneling()
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if isUpload {
		// connect
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshConfig.LocalHost, tu.GetLocalEndpoint().Port()), config)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if conn != nil {
				connErr := conn.Close()
				if connErr != nil {
					logrus.Warnf("connErr: %v", connErr)
				}
			}
		}()

		// create new SFTP client
		client, err := sftp.NewClient(conn)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if client != nil {
				cliErr := client.Close()
				if cliErr != nil {
					logrus.Warnf("cliErr: %v", cliErr)
				}
			}
		}()

		// create destination file
		dstFile, err := client.Create(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if dstFile != nil {
				dstErr := dstFile.Close()
				if dstErr != nil {
					logrus.Warnf("dstErr: %v", dstErr)
				}
			}
		}()

		// create source file
		srcFile, err := os.Open(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}

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

		logrus.Debugf("%d bytes copied to %s\n", written, remotePath)
	} else {
		// connect
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshConfig.LocalHost, tu.GetLocalEndpoint().Port()), config)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if conn != nil {
				clErr := conn.Close()
				if clErr != nil {
					logrus.Warnf("clErr: %v", clErr)
				}
			}
		}()

		// create new SFTP client
		client, err := sftp.NewClient(conn)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if client != nil {
				cliErr := client.Close()
				if cliErr != nil {
					logrus.Warnf("cliErr: %v", cliErr)
				}
			}
		}()

		// create destination file
		dstFile, err := os.Create(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if dstFile != nil {
				dstErr := dstFile.Close()
				if dstErr != nil {
					logrus.Warnf("dstErr: %v", dstErr)
				}
			}
		}()

		// open source file
		srcFile, err := client.Open(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}

		// copy source file to destination file
		written, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		logrus.Debugf("%d bytes copied from %s\n", written, remotePath)

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
func (sc *SSHConfig) Enter(username, shell string) (err error) {
	userPass := ""
	if username != "" && username != sc.User {
		fmt.Printf("Password: ")
		up, err := terminal.ReadPassword(0)
		if err != nil {
			return err
		}
		userPass = string(up)
	}

	sshUsername := username
	if username == "" {
		sshUsername = sc.User
	}

	tu, sshConfig, err := sc.CreateTunneling()
	if err != nil {
		return fmt.Errorf("unable to create tunnels : %s", err.Error())
	}
	defer func() {
		if tu != nil {
			tu.Close()
		}
	}()

	pk, err := sshtunnel.AuthMethodFromPrivateKey([]byte(sshConfig.PrivateKey), nil)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: sc.User, // It should be sshUsername, but we assume no other sc users are allowed
		Auth: []ssh.AuthMethod{
			pk,
		},
		Timeout:         5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	hostport := fmt.Sprintf("%s:%d", "localhost", tu.GetLocalEndpoint().Port())
	conn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		return fmt.Errorf("cannot connect %v: %w", hostport, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open new session: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal make raw: %s", err)
	}
	defer func() {
		_ = terminal.Restore(fd, state)
	}()

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return fmt.Errorf("terminal get size: %s", err)
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
		return fmt.Errorf("session xterm: %s", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// AcceptEnv DEBIAN_FRONTEND
	if sshUsername != "safescale" {
		err = session.Setenv("SAFESCALESSHUSER", sshUsername)
		if err != nil {
			logrus.Debugf("failure setting user terminal: %v", err)
		}
		err = session.Setenv("SAFESCALESSHPASS", userPass)
		if err != nil {
			logrus.Debugf("failure setting user password: %v", err)
		}
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("session shell: %s", err)
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		return fmt.Errorf("sc: %s", err)
	}

	return nil
}

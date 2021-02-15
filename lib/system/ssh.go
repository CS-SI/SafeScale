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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/CS-SI/SafeScale/lib/system/sshtunnel"
	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/pkg/sftp"
)

// SSHConfig helper to manage ssh session
type SSHConfig struct {
	User          string
	Host          string
	PrivateKey    string
	Port          int
	LocalPort     int
	LocalHost     string
	GatewayConfig *SSHConfig
}

// SSHTunnel a SSH tunnel
type SSHTunnel struct {
	cfg  SSHConfig
	port int
}

// CreateTempFileFromString creates a temporary file containing 'content'
func CreateTempFileFromString(content string, filemode os.FileMode) (*os.File, error) {
	defaultTmpDir := "/tmp"
	if runtime.GOOS == "windows" {
		defaultTmpDir = ""
	}

	f, err := ioutil.TempFile(defaultTmpDir, "") // TODO: Windows friendly
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString(content)
	if err != nil {
		logrus.Warnf("Error writing string: %v", err)
	}

	err = f.Chmod(filemode)
	if err != nil {
		logrus.Warnf("Error changing directory: %v", err)
	}

	err = f.Close()
	if err != nil {
		logrus.Warnf("Error closing file: %v", err)
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
func (sc *SSHCommand) Output() (_ []byte, err error) {
	if sc.cmd.Stdout != nil {
		return []byte(""), nil
	}

	defer func() {
		nerr := sc.cleanup()
		if nerr != nil {
			logrus.Warnf("Error waiting for command cleanup: %v", nerr)
			err = nerr
		}
	}()

	content, err := sc.cmd.Output()
	if err != nil {
		return nil, err
	}

	return content, err
}

// Display ...
func (sc *SSHCommand) Display() string {
	return strings.Join(sc.cmd.Args, " ")
}

func (sc *SSHCommand) RunWithTimeout(task concurrency.Task, outs outputs.Enum, timeout time.Duration) (int, string, string, error) {
	tu, _, err := sc.cfg.CreateTunneling()
	if err != nil {
		return 0, "", "", fmt.Errorf("failure creating tunnel: %w", err)
	}
	sc.tunnels = tu
	defer tu.Close()
	rv, out, sterr, err := sc.NewRunWithTimeout(task, outs, timeout)
	return rv, out, sterr, err
}

func PublicKeyFromStr(keyStr string) ssh.AuthMethod {
	key, err := ssh.ParsePrivateKey([]byte(keyStr))
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

// RunWithTimeout ...
func (sc *SSHCommand) NewRunWithTimeout(task concurrency.Task, outs outputs.Enum, timeout time.Duration) (int, string, string, error) {
	tracer := debug.NewTracer(task, fmt.Sprintf("(%s, %v)", outs.String(), timeout), true).WithStopwatch().GoingIn()
	tracer.Trace("command=%s\n", sc.Display())
	defer tracer.OnExitTrace()()

	if task != nil && task.Aborted() {
		return 0, "", "", fail.AbortedError("task aborted by parent", task.GetContext().Err())
	}

	if task != nil && task.Aborted() {
		return 0, "", "", fail.AbortedError("task aborted by parent", task.GetContext().Err())
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
			results <- result{-1, "", "", fail.AbortedError("task aborted by parent", task.GetContext().Err())}
			return
		}

		beginDial := time.Now()
		retries := 0

		var session *ssh.Session
		err = retry.WhileUnsuccessfulTimeout(func() error {
			// Each ClientConn can support multiple interactive sessions,
			// represented by a Session.
			var internalErr error
			session, internalErr = client.NewSession()
			if internalErr == nil {
				logrus.Debugf("creating the session took %s and %d retries", time.Since(beginDial), retries)
			}
			retries = retries + 1
			return internalErr
		}, time.Second, 150*time.Second)
		if err != nil {
			results <- result{
				errorcode: -1,
				stdout:    "",
				stderr:    "",
				reserr:    err,
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
			results <- result{-1, "", "", fail.AbortedError("task aborted by parent", task.GetContext().Err())}
			return
		}

		if sc.cmd == nil {
			results <- result{-1, "", "", fail.AbortedError("nil ssh command!!", nil)}
			return
		}

		if len(sc.cmd.String()) == 0 {
			results <- result{-1, "", "", fail.AbortedError("empty ssh command!!", nil)}
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
			if err := sshtunnel.RunCommandInSshSessionWithTimeout(session, sc.cmd.String(), opTimeout); err != nil {
				logrus.Debugf("Running with session timeout here after %s", time.Since(beginIter))
				errorCode = -1

				if ee, ok := err.(*ssh.ExitError); ok {
					errorCode = ee.ExitStatus()
					logrus.Debugf("Found an exit error of command '%s': %d", sc.cmd.String(), errorCode)
				}

				if _, ok := err.(*ssh.ExitMissingError); ok {
					logrus.Warnf("Found exit missing error of command '%s'", sc.cmd.String())
					errorCode = -1
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
		return
	}()

	if timeout != 0 {
		select {
		case res := <-results:
			if outs == outputs.DISPLAY {
				fmt.Print(res.stdout)
			}
			return res.errorcode, res.stdout, res.stderr, nil
		case <-enough:
			return 255, "", "", fmt.Errorf("received timeout of %s", timeout)
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

// CreateTunneling ...
func (sc *SSHConfig) CreateTunneling() (*sshtunnel.SSHTunnel, *SSHConfig, error) {
	var tu *sshtunnel.SSHTunnel

	if sc.LocalHost == "" {
		sc.LocalHost = "127.0.0.1"
	}

	var gateway *sshtunnel.Endpoint
	if sc.GatewayConfig == nil {
		var rerr error
		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:22", sc.User, sc.Host),
			sshtunnel.EndpointOptionKeyFromString(sc.PrivateKey, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	} else {
		var rerr error
		gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:22", sc.GatewayConfig.User, sc.GatewayConfig.Host),
			sshtunnel.EndpointOptionKeyFromString(sc.GatewayConfig.PrivateKey, ""))
		if rerr != nil {
			return nil, nil, rerr
		}
	}
	server, err := sshtunnel.NewEndpoint(fmt.Sprintf("%s:22", sc.Host),
		sshtunnel.EndpointOptionKeyFromString(sc.PrivateKey, ""))
	if err != nil {
		return nil, nil, err
	}
	local, err := sshtunnel.NewEndpoint(fmt.Sprintf("localhost:%d", sc.LocalPort))
	if err != nil {
		return nil, nil, err
	}
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithLogger(log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)), sshtunnel.TunnelOptionWithDefaultKeepAlive(0))
		if err != nil {
			return nil, nil, err
		}
	} else {
		tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithDefaultKeepAlive(0))
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
		return
	}()

	tunnelReady := <-tu.Ready()
	if !tunnelReady {
		return nil, nil, fmt.Errorf("unable to establish tunnel: %w", tsErr)
	}

	return tu, sc, nil
}

// Command returns the cmd struct to execute cmdString remotely
func (sc *SSHConfig) Command(cmdString string) (*SSHCommand, error) {
	return sc.command(cmdString, false, false)
}

// SudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sc *SSHConfig) SudoCommand(cmdString string) (*SSHCommand, error) {
	return sc.command(cmdString, false, true)
}

func (sc *SSHConfig) command(cmdString string, withTty, withSudo bool) (*SSHCommand, error) {
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
func (sc *SSHConfig) WaitServerReady(task concurrency.Task, phase string, timeout time.Duration) (out string, err error) {
	if sc == nil {
		return "", fail.InvalidInstanceError()
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sc.Host == "" {
		return "", fail.InvalidInstanceContentError("sc.Host", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s',%s)", phase, temporal.FormatDuration(timeout)), false,
	).GoingIn().OnExitTrace()()

	defer fail.OnExitTraceError(
		fmt.Sprintf(
			"timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, sc.Host,
			temporal.FormatDuration(timeout),
		),
		&err,
	)()

	originalPhase := phase
	if phase == "ready" {
		phase = "phase2"
	}

	var (
		retcode        int
		stdout, stderr string
	)
	begins := time.Now()
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			// FIXME: Remove WaitServerReady logs and ensure minimum of iterations
			if task != nil {
				if task != nil && task.Aborted() {
					return fail.AbortedError(fmt.Sprintf("task already aborted by the parent"), nil)
				}
			}

			cmd, err := sc.Command(fmt.Sprintf("sudo cat %s/user_data.%s.done", utils.StateFolder, phase))
			if err != nil {
				return err
			}

			retcode, stdout, stderr, err = cmd.RunWithTimeout(task, outputs.COLLECT, 0)
			if err != nil {
				logrus.Tracef("WaitServerReady: %v", err)
				return err
			}

			var rerr error
			if retcode != 0 {
				if retcode == 255 {
					rerr = fmt.Errorf("remote SSH not ready: error code: 255; Output [%s]; Error [%s]", stdout, stderr)
					logrus.Tracef("WaitServerReady: %v", rerr)
					return rerr
				}
				if retcode == 1 { // File doesn't exist yet
					rerr = fmt.Errorf("remote SSH not ready: error code: 255; Output [%s]; Error [%s]", stdout, stderr)
					logrus.Tracef("WaitServerReady: %v", rerr)
					return rerr
				}
				rerr = fail.AbortedError(
					"",
					fmt.Errorf("remote SSH NOT ready: error code: %d; Output [%s]; Error [%s]", retcode, stdout, stderr),
				)
				logrus.Tracef("WaitServerReady: %v", rerr)
				return rerr
			}

			if stdout == "" && stderr == "" {
				return fmt.Errorf("empty strings cannot happen: the file should contain info about os version and the error code (0) in string format")
			}

			if stdout != "" {
				if !strings.HasPrefix(stdout, "0,") {
					if strings.Contains(stdout, ",") {
						splitted := strings.Split(stdout, ",")
						rerr = fail.AbortedError(fmt.Sprintf("PROVISIONING ERROR: %s", splitted[0]), nil)
						logrus.Tracef("WaitServerReady: %v", rerr)
						return rerr
					}
					rerr = fail.AbortedError(fmt.Sprintf("PROVISIONING ERROR: %s", "Unknown"), nil)
					logrus.Tracef("WaitServerReady: %v", rerr)
					return rerr
				}
			}

			if stderr != "" {
				if !strings.HasPrefix(stderr, "0,") {
					if strings.Contains(stderr, ",") {
						splitted := strings.Split(stderr, ",")
						rerr = fail.AbortedError(fmt.Sprintf("PROVISIONING ERROR: %s", splitted[0]), nil)
						logrus.Tracef("WaitServerReady: %v", rerr)
						return rerr
					}
					rerr = fail.AbortedError(fmt.Sprintf("PROVISIONING ERROR: %s", "Unknown"), nil)
					logrus.Tracef("WaitServerReady: %v", rerr)
					return rerr
				}
			}

			return nil
		},
		timeout,
	)
	if retryErr != nil {
		logrus.Debugf("WaitServerReady: the wait finished with: %v", retryErr)
		return stdout, retryErr
	}
	logrus.Debugf(
		"host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sc.Host, originalPhase,
		temporal.FormatDuration(time.Since(begins)), stdout,
	)
	return stdout, nil
}

// Copy copies a file/directory from/to local to/from remote
func (sc *SSHConfig) Copy(remotePath, localPath string, isUpload bool) (int, string, string, error) {
	tu, sshConfig, err := sc.CreateTunneling()
	if err != nil {
		return -1, "", "", fmt.Errorf("unable to create tunnels : %s", err.Error())
	}
	defer func() {
		if tu != nil {
			tu.Close()
		}
	}()

	pk, err := sshtunnel.AuthMethodFromPrivateKey([]byte(sshConfig.PrivateKey), nil)
	if err != nil {
		return -1, "", "", err
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
			return -1, "", "", err
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
			return -1, "", "", err
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
			return -1, "", "", err
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
			return -1, "", "", err
		}

		// copy source file to destination file
		written, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return -1, "", "", err
		}

		var expected int64
		if fi, err := srcFile.Stat(); err != nil {
			if fi != nil {
				expected = fi.Size()
				if fi.Size() != written {
					return -1, "", "", fmt.Errorf("file size mismatch")
				}
			}
		}

		// it seems copy was ok, but make sure of it
		finfo, err := client.Lstat(remotePath)
		if err != nil {
			return -1, "", "", err
		}
		if expected != 0 {
			if finfo.Size() == 0 {
				return -1, "", "", fmt.Errorf("problem checking file %s: empty file", remotePath)
			}
		}

		logrus.Debugf("%d bytes copied to %s\n", written, remotePath)
	} else {
		// connect
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshConfig.LocalHost, tu.GetLocalEndpoint().Port()), config)
		if err != nil {
			return -1, "", "", err
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
			return -1, "", "", err
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
			return -1, "", "", err
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
			return -1, "", "", err
		}

		// copy source file to destination file
		written, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return -1, "", "", err
		}
		logrus.Debugf("%d bytes copied from %s\n", written, remotePath)

		if fi, err := srcFile.Stat(); err != nil {
			if fi != nil {
				if fi.Size() != written {
					return -1, "", "", fmt.Errorf("file size mismatch")
				}
			}
		}

		// flush in-memory copy
		err = dstFile.Sync()
		if err != nil {
			return -1, "", "", err
		}
	}

	return 0, "", "", nil
}

// Enter Enter to interactive shell
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

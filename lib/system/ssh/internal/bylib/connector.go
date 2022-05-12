/*
  //go:build tunnel
  // +build tunnel
*/
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
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	libssh "golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal/bylib/sshtunnel"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// Connector implements Connector interface using go package ssh
type Connector struct {
	Lock         *sync.RWMutex
	TargetConfig *internal.ConfigProperties
	tunnels      *sshtunnel.SSHTunnel
	// finalConfig   internal.ConfigProperties // contains the ConfigProperties to used to reach the remote server after tunnels have been set
	client *libssh.Client // Contains instance of established connection with target
}

// NewConnector ...
func NewConnector(conf api.Config) (*Connector, fail.Error) {
	casted, ok := conf.(*internal.Config)
	if !ok {
		return nil, fail.InconsistentError("failed to cast 'conf' to '*internal.Config'")
	}

	out := Connector{
		Lock:         new(sync.RWMutex),
		TargetConfig: casted.Properties(),
	}
	return &out, nil
}

// Close cleans up the resources created; ie closes SSH client connection and closes tunnels
func (sc *Connector) Close() fail.Error {
	logrus.Debugf("Closing Connector")

	if sc.client != nil {
		err := sc.client.Close()
		if err != nil {
			return fail.Wrap(err)
		}
		sc.client = nil
	}

	if sc.tunnels != nil {
		sc.tunnels.Close()
		sc.tunnels = nil
	}

	return nil
}

// createTunneling ...
// func (sc *libConnector) createTunneling() (*sshtunnel.SSHTunnel, *ConfigProperties, error) {
func (sc *Connector) createTunneling() fail.Error {
	if sc.tunnels == nil {
		var tu *sshtunnel.SSHTunnel

		internalPort := internal.DefaultPort // all machines use port 22...
		var gateway *sshtunnel.Endpoint
		gwConfig := sc.TargetConfig.GatewayConfig
		if gwConfig == nil { // it has to be a gateway
			internalPort = sc.TargetConfig.Port // ... except maybe the gateway itself

			var rerr error
			gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", sc.TargetConfig.User, sc.TargetConfig.IPAddress, sc.TargetConfig.Port),
				sshtunnel.EndpointOptionKeyFromString(sc.TargetConfig.PrivateKey, ""))
			if rerr != nil {
				return fail.Wrap(rerr)
			}
		} else {
			var rerr error
			gateway, rerr = sshtunnel.NewEndpoint(fmt.Sprintf("%s@%s:%d", gwConfig.User, gwConfig.IPAddress, gwConfig.Port),
				sshtunnel.EndpointOptionKeyFromString(gwConfig.PrivateKey, ""))
			if rerr != nil {
				return fail.Wrap(rerr)
			}
		}

		server, err := sshtunnel.NewEndpoint(fmt.Sprintf("%s:%d", sc.TargetConfig.IPAddress, internalPort),
			sshtunnel.EndpointOptionKeyFromString(sc.TargetConfig.PrivateKey, ""))
		if err != nil {
			return fail.Wrap(err)
		}

		local, err := sshtunnel.NewEndpoint(fmt.Sprintf("localhost:%d", sc.TargetConfig.LocalPort))
		if err != nil {
			return fail.Wrap(err)
		}

		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithLogger(log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)), sshtunnel.TunnelOptionWithDefaultKeepAlive())
			if err != nil {
				return fail.Wrap(err)
			}
		} else {
			tu, err = sshtunnel.NewSSHTunnelFromCfg(*gateway, *server, *local, sshtunnel.TunnelOptionWithDefaultKeepAlive())
			if err != nil {
				return fail.Wrap(err)
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
			return fail.Wrap(tsErr, "unable to establish tunnel: %w")
		}

		sc.tunnels = tu
	}

	return nil
}

// // Command returns the cmd struct to execute cmdString remotely
// func (sc *libConnector) Command(cmdString string) (*libCommand, fail.Error) {
// 	return sc.newCommand(cmdString, false, false)
// }

// NewCommand returns the cmd struct to execute cmdString remotely
func (sc *Connector) NewCommand(_ context.Context, cmdString string) (api.Command, fail.Error) {
	return sc.newCommand(cmdString, false, false)
}

// // SudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
// func (sc *libConnector) SudoCommand(cmdString string) (*libCommand, fail.Error) {
// 	return sc.newCommand(cmdString, false, true)
// }

// NewSudoCommand returns the cmd struct to execute cmdString remotely. Command is executed with sudo
func (sc *Connector) NewSudoCommand(_ context.Context, cmdString string) (api.Command, fail.Error) {
	return sc.newCommand(cmdString, false, true)
}

func (sc *Connector) newCommand(cmdString string, withTty, withSudo bool) (*Command, fail.Error) {
	cmd := exec.Command(cmdString)
	sshCommand := Command{
		withSudo:     withSudo,
		username:     "",
		conn:         sc,
		cmd:          cmd,
		runCmdString: cmdString,
	}
	return &sshCommand, nil
}

// WaitServerReady waits until the SSH server is ready
// the 'timeout' parameter is in minutes
func (sc *Connector) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, err fail.Error) {
	if sc == nil {
		return "", fail.InvalidInstanceError()
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if sc.TargetConfig.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sc.targetConfig.IPAddress()", "cannot be empty string")
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

			cmd, innerXErr := sc.NewCommand(ctx, fmt.Sprintf("sudo cat %s/user_data.%s.done", utils.StateFolder, phase))
			if innerXErr != nil {
				return innerXErr
			}

			var xerr fail.Error
			retcode, stdout, stderr, xerr = cmd.RunWithTimeout(ctx, outputs.COLLECT, 10*time.Second) // FIXME: Remove hardcoded timeout
			if xerr != nil {
				return xerr
			}

			if retcode != 0 {
				fe := fail.NewError("remote SSH NOT ready: error code: %d", retcode)
				fe.Annotate("retcode", retcode)
				fe.Annotate("stdout", stdout)
				fe.Annotate("stderr", stderr)
				fe.Annotate("operation", cmd.String())
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
	logrus.Debugf(
		"host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sc.TargetConfig.IPAddress, originalPhase,
		temporal.FormatDuration(time.Since(begins)), stdout,
	)
	return stdout, nil
}

// CopyWithTimeout ...
func (sc *Connector) CopyWithTimeout(ctx context.Context, remotePath string, localPath string, isUpload bool, timeout time.Duration) (int, string, string, fail.Error) {
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

	// wait anyway until call is finished, then return an error
	// if sc.Copy can handle contexts well, we don't have to wait until it's finished
	// however is not the case here
	<-rCh
	if ctx.Err() != nil {
		return -1, "", "", fail.Wrap(ctx.Err())
	}

	return -1, "", "", fail.NewError("timeout copying...")
}

// Copy copies a file/directory from/to local to/from remote
func (sc *Connector) Copy(ctx context.Context, remotePath string, localPath string, isUpload bool) (_ int, _ string, _ string, ferr fail.Error) {
	// FIXME: Use ctx if it can be handled at lower levels, if not, remove it as a parameter

	// tu, sshConfig, err := sc.createTunneling()
	xerr := sc.createTunneling()
	if xerr != nil {
		return -1, "", "", fail.Wrap(xerr, "unable to create tunnels")
	}

	client, xerr := sc.createTransferClient()
	if xerr != nil {
		return -1, "", "", xerr
	}
	defer func() {
		derr := client.Close()
		if derr != nil {
			// FIXME: return error instead of log?
			logrus.Warn(fail.Wrap(derr, "failed to close SFTP client").Error())
		}
	}()

	if isUpload {
		// create destination file
		dstFile, err := client.Create(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if dstFile != nil {
				dstErr := dstFile.Close()
				if dstErr != nil {
					// FIXME: return error instead of log?
					logrus.Warn(fail.Wrap(dstErr, "failed to close file").Error())
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
		if fi, err := srcFile.Stat(); err != nil && fi != nil {
			expected = fi.Size()
			if fi.Size() != written {
				return -1, "", "", fail.NewError("file size mismatch")
			}
		}

		// it seems copy was ok, but make sure of it
		finfo, err := client.Lstat(remotePath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		if expected != 0 && finfo.Size() == 0 {
			return -1, "", "", fail.NewError("problem checking file %s: empty file", remotePath)
		}

		logrus.Debugf("%d bytes copied to %s\n", written, remotePath)
	} else {
		// create destination file
		dstFile, err := os.Create(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		defer func() {
			if dstFile != nil {
				dstErr := dstFile.Close()
				if dstErr != nil {
					logrus.Warn(fail.Wrap(dstErr, "failed to close file").Error())
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
func (sc *Connector) Enter(username, shell string) (ferr fail.Error) {
	userPass := ""
	if username != "" && username != sc.TargetConfig.User {
		fmt.Printf("Password: ")
		up, err := terminal.ReadPassword(0)
		if err != nil {
			return fail.Wrap(err)
		}
		userPass = string(up)
	}

	sshUsername := username
	if username == "" {
		sshUsername = sc.TargetConfig.User
	}

	// tu, sshConfig, err := sc.createTunneling()
	xerr := sc.createTunneling()
	if xerr != nil {
		return fail.Wrap(xerr, "unable to create tunnels")
	}

	session, xerr := sc.createExecutionSession()
	if xerr != nil {
		return fail.Wrap(xerr, "cannot open new session")
	}
	defer func() {
		_ = session.Close()
	}()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return fail.NewError("terminal make raw: %s", err)
	}
	defer func() {
		_ = terminal.Restore(fd, state)
	}()

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return fail.NewError("terminal get size: %s", err)
	}

	modes := libssh.TerminalModes{
		libssh.ECHO:          1,
		libssh.TTY_OP_ISPEED: 14400,
		libssh.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	if err := session.RequestPty(term, h, w, modes); err != nil {
		return fail.NewError("session xterm: %s", err)
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
		return fail.NewError("session shell: %s", err)
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*libssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			default:
			}
		}
		return fail.NewError("sc: %s", err)
	}

	return nil
}

// createExecutionSession ...
func (sc *Connector) createExecutionSession() (*libssh.Session, fail.Error) {
	sc.Lock.Lock()
	defer sc.Lock.Unlock()

	if sc.client == nil {
		conn, xerr := sc.dial()
		if xerr != nil {
			return nil, xerr
		}
		sc.client = conn
	}

	session, err := sc.client.NewSession()
	if err != nil {
		return nil, fail.Wrap(err, "cannot open new session")
	}

	return session, nil
}

// createTransferClient ...
func (sc *Connector) createTransferClient() (*sftp.Client, fail.Error) {
	sc.Lock.Lock()
	defer sc.Lock.Unlock()

	if sc.client == nil {
		conn, xerr := sc.dial()
		if xerr != nil {
			return nil, xerr
		}
		sc.client = conn
	}

	session, err := sftp.NewClient(sc.client)
	if err != nil {
		return nil, fail.Wrap(err, "cannot open new SFTP session")
	}

	return session, nil
}

// dial establishes connection with remote
func (sc *Connector) dial() (*libssh.Client, fail.Error) {
	pk, err := sshtunnel.AuthMethodFromPrivateKey([]byte(sc.TargetConfig.PrivateKey), nil)
	if err != nil {
		return nil, fail.Wrap(err, "cannot create auth method")
	}

	config := &libssh.ClientConfig{
		User: sc.TargetConfig.User, // It should be sshUsername, but we assume no other sc users are allowed
		Auth: []libssh.AuthMethod{
			pk,
		},
		Timeout:         5 * time.Second,
		HostKeyCallback: libssh.InsecureIgnoreHostKey(),
	}

	hostport := fmt.Sprintf("%s:%d" /*"localhost"*/, internal.Loopback, sc.tunnels.GetLocalEndpoint().Port())
	conn, err := libssh.Dial("tcp", hostport, config)
	if err != nil {
		return nil, fail.Wrap(err, "cannot connect %v", hostport)
	}
	return conn, nil
}

// Config returns an api.Config corresponding to the one belonging to the connector
func (sc Connector) Config() api.Config {
	return internal.ConvertInternalToApiConfig(*sc.TargetConfig)
}

// CreatePersistentTunnel is used to create SSH tunnel that will not be closed on .Close() (unlike createNonPersistentTunnel)
// Used to create persistent tunnel locally with 'safescale tunnel create'
func (sc *Connector) CreatePersistentTunnel() (ferr fail.Error) {
	return fail.InconsistentError("'bylib/Connector' is not able to create persistent SSH tunnel. Use 'bycli/Connector' instead.")
}

//go:build !tunnel
// +build !tunnel

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
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
	//      To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
	//      use the same port for all access to a same host (not the case currently)
	//      May not be used for interactive ssh connection...
	sshOptions = "-q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
)

// Connector implementation using SSH commands
type Connector struct {
	Lock          *sync.RWMutex
	TargetConfig  *internal.ConfigProperties // contains the Config of the remote server
	tunnels       Tunnels                    // Contains all the step to reach the remote server
	targetKeyFile *os.File                   // Contains the file used as key file
	finalConfig   *internal.ConfigProperties // contains the Config to used to reach the remote server after tunnels habe been set
}

// NewConnector ...
func NewConnector(conf api.Config) (*Connector, fail.Error) {
	casted, ok := conf.(*internal.Config)
	if !ok {
		return nil, fail.InconsistentError("failed to cast 'conf' to '*internal.Config'")
	}

	props, xerr := casted.Properties()
	if xerr != nil {
		return nil, xerr
	}

	if !ok {
		return nil, fail.InconsistentError("failed to cast 'conf' to '*internal.Config'")
	}
	out := Connector{
		Lock:         new(sync.RWMutex),
		TargetConfig: props,
	}
	return &out, nil
}

// IsNull tells if the instance is a null value
func (cc *Connector) IsNull() bool {
	return cc == nil || valid.IsNull(cc.TargetConfig)
}

// GetFreePort finds a free port on the system
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

// isTunnelReady tests if the port used for the tunnel is reserved
// If yes, the tunnel is ready, otherwise it failed
func isTunnelReady(port uint) bool {
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
// if localPort is set to 0 then it's automatically chosen
func buildTunnel(scfg *internal.ConfigProperties) (*Tunnel, fail.Error) {
	f, err := utils.CreateTempFileFromString(scfg.GatewayConfig.PrivateKey, 0400)
	if err != nil {
		return nil, err
	}
	// FIXME: temporary file os not removed on failure

	localPort := scfg.LocalPort
	if localPort == 0 {
		localPort, err = getFreePort()
		if err != nil {
			return nil, err
		}
	}

	if scfg.Port == 0 {
		scfg.Port = 22
	}
	if scfg.GatewayConfig.Port == 0 {
		scfg.GatewayConfig.Port = 22
	}
	// VPL: never used in this case...
	// if scfg.SecondaryGatewayConfig != nil && scfg.SecondaryGatewayConfig.Port == 0 {
	// 	scfg.SecondaryGatewayConfig.Port = 22
	// }

	options := sshOptions + " -oServerAliveInterval=60 -oServerAliveCountMax=10" // this survives 10 minutes without connection
	cmdString := fmt.Sprintf(
		"ssh -i \"%s\" -NL 127.0.0.1:%d:%s:%d %s@%s %s -oSendEnv='IAM=%s' -p %d",
		f.Name(),
		localPort,
		scfg.IPAddress,
		scfg.Port,
		scfg.GatewayConfig.User,
		scfg.GatewayConfig.IPAddress,
		options,
		scfg.Hostname,
		scfg.GatewayConfig.Port,
	)

	logrus.Debugf("Creating SSH tunnel with '%s'", cmdString)

	cmd := exec.Command("bash", "-c", cmdString)
	cmd.SysProcAttr = internal.GetSyscallAttrs()
	cerr := cmd.Start()
	if cerr != nil {
		return nil, fail.ConvertError(cerr)
	}

	// gives 10s to build a tunnel, 1s is not enough as the number of tunnels keeps growing
	for nbiter := 0; !isTunnelReady(localPort) && nbiter < 100; nbiter++ {
		time.Sleep(100 * time.Millisecond)
	}

	if !isTunnelReady(localPort) {
		xerr := fail.NotAvailableError("the tunnel is not ready")
		derr := internal.KillProcess(cmd.Process)
		if derr != nil {
			_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to kill SSH process"))
		}
		return nil, xerr
	}

	return &Tunnel{
		port:      localPort,
		cmd:       cmd,
		cmdString: cmdString,
		keyFile:   f,
	}, nil
}

// createConsecutiveTunnels creates recursively all the SSH tunnels hops needed to reach the remote
func createConsecutiveTunnels(sci *internal.ConfigProperties, tunnels *Tunnels) (*Tunnel, fail.Error) {
	// var (
	// 	tunnel *Tunnel
	// 	xerr fail.Error
	// )
	// if sci.GatewayConfig != nil {
	// 	tunnel, xerr = createConsecutiveTunnels(*sci.GatewayConfig, tunnels)
	// 	if xerr != nil {
	// 		return nil, xerr
	// 	}
	// }
	//
	// cfg := sci
	// if tunnel != nil {
	// 	gateway := sci.GatewayConfig
	// 	gateway.Port = tunnel.port
	// 	gateway.IPAddress = "127.0.0.1"
	// 	cfg.GatewayConfig = gateway
	// }
	// if cfg.GatewayConfig != nil {
	// 	failures := 0
	// 	xerr = retry.WhileUnsuccessful(
	// 		func() error {
	// 			tunnel, xerr = buildTunnel(&cfg)
	// 			if xerr != nil {
	// 				switch xerr.(type) {
	// 				case *fail.ErrNotAvailable: // When this happens, resources are close to exhaustion
	// 					failures++
	// 					if failures > 6 { // TODO: retry lib should provide some kind of circuit-breaker pattern
	// 						return retry.StopRetryError(xerr, "not enough resources, pointless to retry")
	// 					}
	// 					return xerr
	// 				default:
	// 					return xerr
	// 				}
	// 			}
	//
	// 			// Note: provokes LIFO (Last In First Out) during the deletion of tunnels
	// 			*tunnels = append(Tunnels{tunnel}, *tunnels...)
	// 			return nil
	// 		},
	// 		temporal.DefaultDelay(),
	// 		temporal.OperationTimeout(),
	// 	)
	// 	if xerr != nil {
	// 		switch xerr.(type) { // nolint
	// 		case *retry.ErrStopRetry:
	// 			return nil, fail.Wrap(fail.Cause(xerr))
	// 		case *retry.ErrTimeout:
	// 			return nil, fail.ConvertError(fail.Cause(xerr))
	// 		}
	// 		return nil, xerr
	// 	}
	// 	return tunnel, nil
	// }
	if sci != nil {
		// determine what gateway to use
		gwConf, xerr := internal.DetermineRespondingGateway([]*internal.ConfigProperties{sci.GatewayConfig, sci.SecondaryGatewayConfig})
		if xerr != nil {
			return nil, xerr
		}

		tunnel, xerr := createConsecutiveTunnels(gwConf, tunnels)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotAvailable:
				gwConf = sci.SecondaryGatewayConfig
				tunnel, xerr = createConsecutiveTunnels(gwConf, tunnels)
				if xerr != nil {
					return nil, xerr
				}
			default:
				return nil, xerr
			}
		}

		if gwConf != nil {
			cfg, xerr := sci.Clone()
			if xerr != nil {
				return nil, xerr
			}
			cfg.GatewayConfig = gwConf
			if tunnel != nil {
				gateway := *gwConf
				gateway.Port = tunnel.port
				gateway.IPAddress = "127.0.0.1"
				cfg.GatewayConfig = &gateway
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

// CreatePersistentTunnel is used to create SSH tunnel that will not be closed on .Close() (unlike createTransientTunnel)
// Used to create persistent tunnel locally with 'safescale tunnel create'
func (cc *Connector) CreatePersistentTunnel() (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(cc) {
		// return nil, internalConfig{}, fail.InvalidInstanceError()
		return fail.InvalidInstanceError()
	}

	cc.Lock.Lock()
	defer cc.Lock.Unlock()

	_, _, xerr := cc.createTunnel()
	if xerr != nil {
		return xerr
	}

	return nil
}

// createTunnel build tunnels to reach target carried by Connector
func (cc Connector) createTunnel() (_ *internal.ConfigProperties, _ Tunnels, ferr fail.Error) {
	var tunnels Tunnels
	defer func() {
		if ferr != nil {
			derr := cc.deleteTunnels()
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to close SSH tunnels"))
			}
		}
	}()

	tunnel, xerr := createConsecutiveTunnels(cc.TargetConfig, &tunnels)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to create SSH Tunnels")
	}

	newConf, xerr := cc.TargetConfig.Clone()
	if xerr != nil {
		return nil, nil, xerr
	}
	if tunnel == nil {
		return newConf, tunnels, nil
	}

	if cc.TargetConfig.GatewayConfig != nil {
		newConf.Port = tunnel.port
		newConf.IPAddress = internal.Loopback
		if xerr != nil {
			return nil, nil, xerr
		}
	}
	return newConf, tunnels, nil
}

// createTransientTunnel creates a tunnel that will end with Connector instance (ie non persistent)
func (cc *Connector) createTransientTunnel() (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(cc) {
		// return nil, internalConfig{}, fail.InvalidInstanceError()
		return fail.InvalidInstanceError()
	}

	if len(cc.tunnels) == 0 {
		cc.Lock.Lock()
		defer cc.Lock.Unlock()

		newConf, tunnels, xerr := cc.createTunnel()
		if xerr != nil {
			return xerr
		}

		// Keep track of tunnel in Connector
		cc.finalConfig = newConf
		cc.tunnels = tunnels
	}
	return nil
}

// func buildSSHCommand(sconf Config, cmdString, username, shell string, withTty, withSudo bool) (string, *os.File, fail.Error) {
func (cc *Connector) buildSSHCommand(cmdString, username, shell string, withTty, withSudo bool) (string, fail.Error) {
	// f, err := utils.CreateTempFileFromString(sconf._private.PrivateKey, 0400)
	// if err != nil {
	// 	return "", nil, fail.Wrap(err, "unable to create temporary key file")
	// }

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", cc.finalConfig.Hostname)
	sshCmdString := fmt.Sprintf("ssh -i \"%s\" %s -p %d %s@%s", cc.targetKeyFile.Name(), options, cc.finalConfig.Port, cc.finalConfig.User, cc.finalConfig.IPAddress)

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

	return sshCmdString, nil
}

// NewCommand returns the cmd struct to execute runCmdString remotely
func (cc *Connector) NewCommand(ctx context.Context, cmdString string) (api.Command, fail.Error) {
	return cc.newExecuteCommand(ctx, cmdString, false, false)
}

// NewSudoCommand returns the cmd struct to execute runCmdString remotely. NewCommand is executed with sudo
func (cc *Connector) NewSudoCommand(ctx context.Context, cmdString string) (api.Command, fail.Error) {
	return cc.newExecuteCommand(ctx, cmdString, false, true)
}

func (cc *Connector) newExecuteCommand(ctx context.Context, cmdString string, withTty, withSudo bool) (_ *Command, ferr fail.Error) {
	if valid.IsNull(cc) {
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

	xerr = cc.createTransientTunnel()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to create SSH tunnel")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	xerr = cc.createTargetKeyfile()
	if xerr != nil {
		return nil, xerr
	}

	// sshCmdString, keyFile, err := buildSSHCommand(tunnelingConfig, cmdString, "", "", withTty, withSudo)
	sshCmdString, xerr := cc.buildSSHCommand(cmdString, "", "", withTty, withSudo)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to create command")
	}

	sshCommand := Command{
		conn:         cc,
		hostname:     cc.TargetConfig.Hostname,
		runCmdString: sshCmdString,
	}
	return &sshCommand, nil
}

// createTargetKeyFile creates a temporary file containing key to authenticate the remote (if not already created)
func (cc *Connector) createTargetKeyfile() fail.Error {
	cc.Lock.Lock()
	defer cc.Lock.Unlock()

	// If key file is not created yet, do it
	if cc.targetKeyFile == nil {
		keyFile, xerr := utils.CreateTempFileFromString(cc.TargetConfig.PrivateKey, 0400)
		if xerr != nil {
			return xerr
		}

		cc.targetKeyFile = keyFile
	}

	return nil
}

// newCopyCommand does the same thing as newExecuteCommand for SCP actions
func (cc *Connector) newCopyCommand(ctx context.Context, localPath, remotePath string, isUpload bool) (*Command, fail.Error) {
	if valid.IsNull(cc) {
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

	// sshCmdString, keyFile, xerr := buildSCPCommand(tunnelConfig, localPath, remotePath, isUpload)
	sshCmdString, xerr := cc.buildSCPCommand(localPath, remotePath, isUpload)
	if xerr != nil {
		return nil, xerr
	}

	sshCommand := Command{
		conn:         cc,
		hostname:     cc.TargetConfig.Hostname,
		runCmdString: sshCmdString,
	}
	return &sshCommand, nil
}

// buildSCPCommand Creates the scp command to do the copy
// func buildSCPCommand(sconf Config, localPath, remotePath string, isUpload bool) (string, *os.File, fail.Error) {
func (cc *Connector) buildSCPCommand(localPath, remotePath string, isUpload bool) (string, fail.Error) {
	// f, err := utils.CreateTempFileFromString(sconf._private.PrivateKey, 0400)
	// if err != nil {
	// 	return "", nil, fail.Wrap(err, "unable to create temporary key file")
	// }

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", cc.finalConfig.Hostname)

	sshCmdString := fmt.Sprintf("scp -i \"%s\" %s -P %d ", cc.targetKeyFile.Name(), options, cc.finalConfig.Port)
	if isUpload {
		sshCmdString += fmt.Sprintf("\"%s\" %s@%s:%s", localPath, cc.finalConfig.User, cc.finalConfig.IPAddress, remotePath)
	} else {
		sshCmdString += fmt.Sprintf("%s@%s:%s \"%s\"", cc.finalConfig.User, cc.finalConfig.IPAddress, remotePath, localPath)
	}

	// return sshCmdString, f, nil
	return sshCmdString, nil
}

// WaitServerReady waits until the SSH server is ready
func (cc *Connector) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(cc) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}
	if cc.TargetConfig.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("cc.conf", "ssh targetConfig does not contain valid IP Address for remote")
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
		&xerr, "timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, cc.TargetConfig.Hostname,
		temporal.FormatDuration(timeout),
	)

	xerr = cc.createTransientTunnel()
	if xerr != nil {
		return "", fail.Wrap(xerr, "unable to create private key file")
	}

	xerr = cc.createTargetKeyfile()
	if xerr != nil {
		return "", fail.Wrap(xerr, "unable to create private key file")
	}

	originalPhase := phase
	if phase == "ready" {
		phase = "final"
	}

	var (
		stdout, stderr string
	)

	closeTunnelsFunc := func(deferErr *fail.Error) {
		derr := cc.deleteTunnels()
		if derr != nil && deferErr != nil {
			if *deferErr != nil {
				*deferErr = fail.Wrap(*deferErr)
				_ = (*deferErr).AddConsequence(derr)
			} else {
				*deferErr = derr
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
			sshCmd, innerXErr := cc.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.%s.done", utils.VarFolder, phase))
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = cc.createTransientTunnel()
			if xerr != nil {
				return fail.Wrap(xerr, "unable to create tunnels")
			}

			// in case of failure, maybe tunnels was badly built, delete it to rebuild
			defer closeTunnelsFunc(&innerXErr)

			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 { // nolint
				switch phase {
				case "final":
					// Before v21.05.0, final provisioning state is stored in user_data.phase2.done file, so try to see if legacy file exists...
					sshCmd, innerXErr = cc.NewCommand(ctx, fmt.Sprintf("sudo cat %s/state/user_data.phase2.done", utils.VarFolder))
					if innerXErr != nil {
						return innerXErr
					}

					// VPL: there is nothing to close from Command anymore
					// // Do not forget to close command, ie close SSH tunnels
					// defer func(cmd Command) { cmdCloseFunc(cmd, &innerXErr) }(sshCmd)

					retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
					if innerXErr != nil {
						return innerXErr
					}
				default:
				}
			}
			if retcode != 0 {
				fe := fail.NewError("remote SSH NOT ready: error code: %d", retcode)
				fe.Annotate("operation", sshCmd.String())
				fe.Annotate("retcode", retcode)
				fe.Annotate("stdout", stdout)
				fe.Annotate("stderr", stderr)
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

	logrus.Debugf("host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", cc.TargetConfig.Hostname, originalPhase, temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// CopyWithTimeout copies a file/directory from/to local to/from remote, and fails after 'timeout'
func (cc *Connector) CopyWithTimeout(ctx context.Context, remotePath, localPath string, isUpload bool, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	const invalid = -1
	if valid.IsNull(cc) {
		return invalid, "", "", fail.InvalidInstanceError()
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	xerr = cc.createTransientTunnel()
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "unable to create tunnels")
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	xerr = cc.createTargetKeyfile()
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "unable to create private key file")
	}

	sshCommand, xerr := cc.newCopyCommand(ctx, localPath, remotePath, isUpload)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to create copy command")
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	return sshCommand.RunWithTimeout(ctx, outputs.COLLECT, timeout)
}

// Enter to interactive shell, aka 'safescale ssh connect'
func (cc *Connector) Enter(username, shell string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(cc) {
		return fail.InvalidInstanceError()
	}

	xerr := cc.createTargetKeyfile()
	if xerr != nil {
		return fail.Wrap(xerr, "unable to create private key file")
	}

	xerr = cc.createTransientTunnel()
	if xerr != nil {
		return fail.Wrap(xerr, "unable to create tunnels")
	}

	// VPL: moved to Connector.Close()
	// // Do not forget to close tunnels...
	// defer func() {
	// 	derr := cc.tunnels.Close()
	// 	if derr != nil {
	// 		if ferr != nil {
	// 			_ = ferr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnels"))
	// 		} else {
	// 			ferr = derr
	// 		}
	// 	}
	// }()

	// sshCmdString, keyFile, xerr := buildSSHCommand(tunnelConfig, "", username, shell, true, false)
	sshCmdString, xerr := cc.buildSSHCommand("", username, shell, true, false)
	if xerr != nil {
		// for _, t := range tunnels {
		// 	if nerr := t.Close(); nerr != nil {
		// 		logrus.Warnf("Error closing SSH tunnel: %v", nerr)
		// 	}
		// }
		// if keyFile != nil {
		// 	if nerr := utils.LazyRemove(keyFile.Name()); nerr != nil {
		// 		logrus.Warnf("Error removing file %v", nerr)
		// 	}
		// }
		return fail.Wrap(xerr, "unable to create command")
	}

	// defer func() {
	// 	derr := utils.LazyRemove(keyFile.Name())
	// 	if derr != nil {
	// 		logrus.Warnf("Error removing temporary file: %v", derr)
	// 	}
	// }()

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

// Close cleans up the resources created by the connector (keyfile, tunnels, ...)
func (cc *Connector) Close() fail.Error {
	if valid.IsNull(cc) {
		return fail.InvalidInstanceError()
	}

	var errors []error

	// Close tunnels if there are some
	xerr := cc.deleteTunnels()
	if xerr != nil {
		errors = append(errors, xerr)
	}
	cc.finalConfig = nil

	// Delete key file if there is one
	xerr = cc.deleteKeyfile()
	if xerr != nil {
		errors = append(errors, xerr)
	}

	if len(errors) > 0 {
		return fail.Wrap(fail.NewErrorList(errors), "failed to close SSH Connector properly")
	}

	return nil
}

// deleteTunnels closes the tunnel (if there are some)
func (cc *Connector) deleteTunnels() fail.Error {
	if len(cc.tunnels) > 0 {
		xerr := cc.tunnels.Close()
		if xerr != nil {
			return fail.Wrap(xerr, "failed to close SSH tunnels")
		}
		cc.tunnels = nil
	}

	return nil
}

// deleteKeyfile removes the temporary file containig key file (if there is one)
func (cc *Connector) deleteKeyfile() fail.Error {
	if cc.targetKeyFile != nil {
		name := cc.targetKeyFile.Name()
		cc.targetKeyFile = nil

		xerr := utils.LazyRemove(name)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

func (cc Connector) Config() (api.Config, fail.Error) {
	return internal.ConvertInternalToAPIConfig(*cc.TargetConfig)
}

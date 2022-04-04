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

package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
)

const (
	PrimaryGateway   uint8 = 0
	SecondaryGateway uint8 = 1
)

const (
	// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
	//      To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
	//      use the same port for all access to a same host (not the case currently)
	//      May not be used for interactive ssh connection...
	sshOptions = "-q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
)

// Config helper to manage ssh session
type Config interface {
	CopyWithTimeout(context.Context, string, string, bool, time.Duration) (int, string, string, fail.Error)
	CreateTunneling() (Tunnels, Config, fail.Error)
	Enter(string, string) fail.Error
	GatewayConfig(uint8) (Config, fail.Error)
	Hostname() string
	IPAddress() string
	LocalPort() uint
	NewCommand(context.Context, string) (*Command, fail.Error)
	NewSudoCommand(context.Context, string) (*Command, fail.Error)
	Port() uint
	PrimaryGatewayConfig() (Config, fail.Error)
	PrivateKey() string
	SecondaryGatewayConfig() (Config, fail.Error)
	SetGatewayConfig(uint8, Config) fail.Error
	User() string
	WaitServerReady(context.Context, string, time.Duration) (string, fail.Error)
}

// sshConfig helper to manage ssh session
type sshConfig struct {
	// user                   string
	// ipAddress              string
	// privateKey             string
	// hostname               string
	// gatewayConfig          *sshConfig
	// secondaryGatewayConfig *sshConfig
	// port                   int
	// localPort              int
	_private sshConfigInternal
}

type sshConfigInternal struct {
	User                   string             `json:"user"`
	IPAddress              string             `json:"ip_address"`
	PrivateKey             string             `json:"private_key"`
	Hostname               string             `json:"hostname"`
	GatewayConfig          *sshConfigInternal `json:"primary_gateway_config,omitempty"`
	SecondaryGatewayConfig *sshConfigInternal `json:"secondary_gateway_config,omitempty"`
	Port                   uint               `json:"port"`
	LocalPort              uint               `json:"-"`
}

func NewConfig(hostname, ipAddress string, port uint, user, privateKey string, gws ...Config) (Config, fail.Error) {
	out := &sshConfig{
		_private: sshConfigInternal{
			User:       user,
			Hostname:   hostname,
			IPAddress:  ipAddress,
			Port:       port,
			PrivateKey: privateKey,
		},
	}

	if len(gws) > 0 {
		gw := gws[PrimaryGateway]
		if gw != nil {
			xerr := out.SetGatewayConfig(PrimaryGateway, gw)
			if xerr != nil {
				return nil, xerr
			}
		}
	}

	if len(gws) > 1 {
		gw := gws[SecondaryGateway]
		if gw != nil {
			xerr := out.SetGatewayConfig(SecondaryGateway, gw)
			if xerr != nil {
				return nil, xerr
			}
		}
	}

	return out, nil
}

func (sconf *sshConfig) SetGatewayConfig(idx uint8, gwConfig Config) fail.Error {
	if valid.IsNil(sconf) {
		return fail.InvalidInstanceError()
	}
	if idx > 1 {
		return fail.InvalidParameterError("idx", "must be 0 for mprimary gateway or 1 for secondary gateway")
	}

	conf := sshConfigInternal{
		User:       gwConfig.User(),
		IPAddress:  gwConfig.IPAddress(),
		PrivateKey: gwConfig.PrivateKey(),
		Hostname:   gwConfig.Hostname(),
		Port:       gwConfig.Port(),
		LocalPort:  gwConfig.LocalPort(),
	}
	switch idx {
	case PrimaryGateway:
		sconf._private.GatewayConfig = &conf
	case SecondaryGateway:
		sconf._private.SecondaryGatewayConfig = &conf
	}

	return nil
}

func (sconf sshConfig) MarshalJSON() ([]byte, error) {
	jsoned, err := json.Marshal(sconf._private)
	if err != nil {
		return nil, err
	}
	return jsoned, nil
}

func (sconf *sshConfig) UnmarshalJSON(in []byte) error {
	if sconf == nil {
		return fail.InvalidInstanceError()
	}

	err := json.Unmarshal(in, &sconf._private)
	if err != nil {
		return err
	}

	return nil
}

// IsNull tells if the instance is a null value
func (sconf *sshConfig) IsNull() bool {
	return sconf == nil || sconf._private.IPAddress == ""
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
func buildTunnel(scfg sshConfigInternal) (*Tunnel, fail.Error) {
	f, err := utils.CreateTempFileFromString(scfg.GatewayConfig.PrivateKey, 0400)
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

	if scfg.Port == 0 {
		scfg.Port = 22
	}
	if scfg.GatewayConfig.Port == 0 {
		scfg.GatewayConfig.Port = 22
	}
	if scfg.SecondaryGatewayConfig != nil && scfg.SecondaryGatewayConfig.Port == 0 {
		scfg.SecondaryGatewayConfig.Port = 22
	}

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
	cmd.SysProcAttr = getSyscallAttrs()
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
		derr := killProcess(cmd.Process)
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
func createConsecutiveTunnels(sc sshConfigInternal, tunnels *Tunnels) (*Tunnel, fail.Error) {
	tunnel, xerr := createConsecutiveTunnels(*sc.GatewayConfig, tunnels)
	if xerr != nil {
		return nil, xerr
	}

	cfg := sc
	if tunnel != nil {
		gateway := *sc.GatewayConfig
		gateway.Port = tunnel.port
		gateway.IPAddress = "127.0.0.1"
		cfg.GatewayConfig = &gateway
	}
	if cfg.GatewayConfig != nil {
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
	return nil, nil
}

// CreateTunneling ...
func (sconf *sshConfig) CreateTunneling() (_ Tunnels, _ Config, ferr fail.Error) {
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

	tunnel, xerr := createConsecutiveTunnels(sconf._private, &tunnels)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to create SSH Tunnels")
	}

	newConf := *sconf
	if tunnel == nil {
		return nil, &newConf, nil
	}

	if sconf._private.GatewayConfig != nil {
		newConf._private.Port = tunnel.port
		newConf._private.IPAddress = "127.0.0.1"
	}
	return tunnels, &newConf, nil
}

func createSSHCommand(sconf *sshConfig, cmdString, username, shell string, withTty, withSudo bool) (string, *os.File, fail.Error) {
	f, err := utils.CreateTempFileFromString(sconf._private.PrivateKey, 0400)
	if err != nil {
		return "", nil, fail.Wrap(err, "unable to create temporary key file")
	}

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", sconf.Hostname())
	sshCmdString := fmt.Sprintf("ssh -i \"%s\" %s -p %d %s@%s", f.Name(), options, sconf.Port(), sconf.User(), sconf.IPAddress())

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
func (sconf *sshConfig) NewCommand(ctx context.Context, cmdString string) (*Command, fail.Error) {
	return sconf.newCommand(ctx, cmdString, false, false)
}

// NewSudoCommand returns the cmd struct to execute runCmdString remotely. NewCommand is executed with sudo
func (sconf *sshConfig) NewSudoCommand(ctx context.Context, cmdString string) (*Command, fail.Error) {
	return sconf.newCommand(ctx, cmdString, false, true)
}

func (sconf *sshConfig) newCommand(ctx context.Context, cmdString string, withTty, withSudo bool) (*Command, fail.Error) {
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

	tunnels, tunnelConf, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to create SSH tunnel")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tunnelConfig, ok := tunnelConf.(*sshConfig)
	if !ok {
		return nil, fail.InconsistentError("failed to cast tunnelConf to '*sshConfig'")
	}

	sshCmdString, keyFile, err := createSSHCommand(tunnelConfig, cmdString, "", "", withTty, withSudo)
	if err != nil {
		return nil, fail.Wrap(err, "unable to create command")
	}

	sshCommand := Command{
		hostname:     sconf._private.Hostname,
		runCmdString: sshCmdString,
		tunnels:      tunnels,
		keyFile:      keyFile,
	}
	return &sshCommand, nil
}

// newCopyCommand does the same thing as newCommand for SCP actions
func (sconf *sshConfig) newCopyCommand(ctx context.Context, localPath, remotePath string, isUpload bool) (*Command, fail.Error) {
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

	tunnels, tunnelConf, xerr := sconf.CreateTunneling()
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tunnelConfig, ok := tunnelConf.(*sshConfig)
	if !ok {
		return nil, fail.InconsistentError("failed to cast tunnelConfig to '*sshConfig'")
	}
	sshCmdString, keyFile, xerr := createSCPCommand(tunnelConfig, localPath, remotePath, isUpload)
	if xerr != nil {
		return nil, xerr
	}

	sshCommand := Command{
		hostname:     sconf._private.Hostname,
		runCmdString: sshCmdString,
		tunnels:      tunnels,
		keyFile:      keyFile,
	}
	return &sshCommand, nil
}

// createSCPCommand Creates the scp command to do the copy
func createSCPCommand(sconf *sshConfig, localPath, remotePath string, isUpload bool) (string, *os.File, fail.Error) {
	f, err := utils.CreateTempFileFromString(sconf._private.PrivateKey, 0400)
	if err != nil {
		return "", nil, fail.Wrap(err, "unable to create temporary key file")
	}

	options := sshOptions + " -oConnectTimeout=60 -oLogLevel=error" + fmt.Sprintf(" -oSendEnv='IAM=%s'", sconf.Hostname())

	sshCmdString := fmt.Sprintf("scp -i \"%s\" %s -P %d ", f.Name(), options, sconf.Port())
	if isUpload {
		sshCmdString += fmt.Sprintf("\"%s\" %s@%s:%s", localPath, sconf.User(), sconf.IPAddress(), remotePath)
	} else {
		sshCmdString += fmt.Sprintf("%s@%s:%s \"%s\"", sconf.User(), sconf.IPAddress(), remotePath, localPath)
	}

	return sshCmdString, f, nil
}

// WaitServerReady waits until the SSH server is ready
func (sconf *sshConfig) WaitServerReady(ctx context.Context, phase string, timeout time.Duration) (out string, ferr fail.Error) {
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
	if sconf._private.IPAddress == "" {
		return "", fail.InvalidInstanceContentError("sconf._private.IPAddress", "cannot be empty string")
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
		&xerr, "timeout waiting remote SSH phase '%s' of host '%s' for %s", phase, sconf.Hostname(),
		temporal.FormatDuration(timeout),
	)

	originalPhase := phase
	if phase == "ready" {
		phase = "final"
	}

	var (
		stdout, stderr string
	)

	cmdCloseFunc := func(cmd *Command, deferErr *fail.Error) {
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
			defer func(cmd *Command) { cmdCloseFunc(cmd, &innerXErr) }(sshCmd)

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
					defer func(cmd *Command) { cmdCloseFunc(cmd, &innerXErr) }(sshCmd)

					retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, timeout/4)
					if innerXErr != nil {
						return innerXErr
					}
				default:
				}
			}
			if retcode != 0 {
				fe := fail.NewError("remote SSH NOT ready: error code: %d", retcode)
				fe.Annotate("retcode", retcode)
				fe.Annotate("stdout", stdout)
				fe.Annotate("stderr", stderr)
				fe.Annotate("operation", sshCmd.runCmdString)
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

	logrus.Debugf("host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", sconf.Hostname(), originalPhase, temporal.FormatDuration(time.Since(begins)), stdout)
	return stdout, nil
}

// CopyWithTimeout copies a file/directory from/to local to/from remote, and fails after 'timeout'
func (sconf *sshConfig) CopyWithTimeout(ctx context.Context, remotePath, localPath string, isUpload bool, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	const invalid = -1
	if valid.IsNil(sconf) {
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
func (sconf *sshConfig) Enter(username, shell string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tunnels, tunnelConf, xerr := sconf.CreateTunneling()
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

	tunnelConfig, ok := tunnelConf.(*sshConfig)
	if !ok {
		return fail.InconsistentError("failed to cast tunnelConf to *sshConfig")
	}

	sshCmdString, keyFile, xerr := createSSHCommand(tunnelConfig, "", username, shell, true, false)
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

// PrivateKey ...
func (sconf sshConfig) PrivateKey() string {
	return sconf._private.PrivateKey
}

// User ...
func (sconf sshConfig) User() string {
	return sconf._private.User
}

// Hostname ...
func (sconf sshConfig) Hostname() string {
	return sconf._private.Hostname
}

// IPAddress ...
func (sconf sshConfig) IPAddress() string {
	_ = sshConfigInternal{}
	return sconf._private.Hostname
}

// GatewayConfig ...
func (sconf sshConfig) GatewayConfig(idx uint8) (Config, fail.Error) {
	if idx > 1 {
		return nil, fail.InvalidParameterError("idx", "must be 0 for primary gateway or 1 for secondary gateway")
	}

	var newConf *sshConfigInternal
	switch idx {
	case PrimaryGateway:
		newConf = sconf._private.GatewayConfig
	case SecondaryGateway:
		newConf = sconf._private.SecondaryGatewayConfig
	default:
		return nil, fail.InvalidParameterError("idx", "must be 0 for primary or 1 for secondary gateway")
	}

	out := sshConfig{
		_private: *newConf,
	}
	return &out, nil
}

// PrimaryGatewayConfig ...
func (sconf sshConfig) PrimaryGatewayConfig() (Config, fail.Error) {
	return sconf.GatewayConfig(0)
}

// SecondaryGatewayConfig ...
func (sconf sshConfig) SecondaryGatewayConfig() (Config, fail.Error) {
	return sconf.GatewayConfig(1)
}

// Port ...
func (sconf sshConfig) Port() uint {
	return sconf._private.Port
}

// LocalPort ...
func (sconf sshConfig) LocalPort() uint {
	return sconf._private.LocalPort
}

/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/CS-SI/SafeScale/utils/retry"
	"golang.org/x/crypto/ssh"
)

//SSHConfig helper to manage ssh session
type SSHConfig struct {
	User          string
	Host          string
	PrivateKey    string
	Port          int
	GatewayConfig *SSHConfig
	cmdTpl        string
}

//SSHTunnel a SSH tunnel
type sshTunnel struct {
	port      int
	cmd       *exec.Cmd
	cmdString string
	keyFile   *os.File
}

//Close close ssh tunnel
func (tunnel *sshTunnel) Close() error {
	defer os.Remove(tunnel.keyFile.Name())

	err := tunnel.cmd.Process.Kill()
	if err != nil {
		return fmt.Errorf("Unable to close tunnel :%s", err.Error())
	}
	bytes, err := exec.Command("pgrep", "-f", tunnel.cmdString).Output()
	if err != nil {
		return fmt.Errorf("Unable to close tunnel :%s", err.Error())
	}
	portStr := strings.Trim(string(bytes), "\n")
	_, err = strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("Unable to close tunnel :%s", err.Error())
	}
	err = exec.Command("kill", "-9", portStr).Run()
	if err != nil {
		return fmt.Errorf("Unable to close tunnel :%s", err.Error())
	}
	return nil
}

//GetFreePort get a frre port
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	defer listener.Close()
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, nil
}

// CreateTempFileFromString creates a tempory file containing 'content'
func CreateTempFileFromString(content string) (*os.File, error) {
	f, err := ioutil.TempFile("/tmp", "")
	if err != nil {
		return nil, err
	}
	f.WriteString(content)
	f.Chmod(0400)
	f.Close()
	return f, nil
}

func isTunnelReady(port int) bool {
	// Try to create a server with the port
	server, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	server.Close()
	return false

}

//CreateTunnel create SSH from local host to remote host throw gateway
func createTunnel(cfg *SSHConfig) (*sshTunnel, error) {
	f, err := CreateTempFileFromString(cfg.GatewayConfig.PrivateKey)
	if err != nil {
		return nil, err
	}
	freePort, err := getFreePort()
	if err != nil {
		return nil, err
	}
	options := "-q -oServerAliveInterval=60 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"
	cmdString := fmt.Sprintf("ssh -i %s -NL %d:%s:%d %s@%s %s -p %d",
		f.Name(),
		freePort,
		cfg.Host,
		cfg.Port,
		cfg.GatewayConfig.User,
		cfg.GatewayConfig.Host,
		options,
		cfg.GatewayConfig.Port,
	)
	cmd := exec.Command("sh", "-c", cmdString)
	err = cmd.Start()
	//	err = cmd.Wait()
	if err != nil {
		return nil, err
	}

	for nbiter := 0; !isTunnelReady(freePort) && nbiter < 100; nbiter++ {
		time.Sleep(10 * time.Millisecond)
	}
	return &sshTunnel{
		port:      freePort,
		cmd:       cmd,
		cmdString: cmdString,
		keyFile:   f,
	}, nil
}

//SSHCommand defines a SSH command
type SSHCommand struct {
	cmd     *exec.Cmd
	tunnels []*sshTunnel
	keyFile *os.File
}

func (c *SSHCommand) closeTunnels() error {
	var err error
	for _, t := range c.tunnels {
		err = t.Close()
	}
	//Tunnels are imbricated only last error is significant
	return err
}

// Wait waits for the command to exit and waits for any copying to stdin or copying from stdout or stderr to complete.
// The command must have been started by Start.
// The returned error is nil if the command runs, has no problems copying stdin, stdout, and stderr, and exits with a zero exit status.
// If the command fails to run or doesn't complete successfully, the error is of type *ExitError. Other error types may be returned for I/O problems.
// Wait also waits for the I/O loop copying from c.Stdin into the process's standard input to complete.
// Wait releases any resources associated with the Cmd.
func (c *SSHCommand) Wait() error {
	err := c.cmd.Wait()
	c.end()
	return err

}

//Kill kills SSHCommand process and releases any resources associated with the SSHCommand.
func (c *SSHCommand) Kill() error {
	err := c.cmd.Process.Kill()
	c.end()
	return err
}

//StdoutPipe returns a pipe that will be connected to the command's standard output when the command starts.
//Wait will close the pipe after seeing the command exit, so most callers need not close the pipe themselves; however, an implication is that it is incorrect to call Wait before all reads from the pipe have completed.
//For the same reason, it is incorrect to call Run when using StdoutPipe.
func (c *SSHCommand) StdoutPipe() (io.ReadCloser, error) {
	return c.cmd.StdoutPipe()
}

// StderrPipe returns a pipe that will be connected to the command's standard error when the command starts.
// Wait will close the pipe after seeing the command exit, so most callers need not close the pipe themselves; however, an implication is that it is incorrect to call Wait before all reads from the pipe have completed. For the same reason, it is incorrect to use Run when using StderrPipe.
func (c *SSHCommand) StderrPipe() (io.ReadCloser, error) {
	return c.cmd.StderrPipe()
}

//StdinPipe returns a pipe that will be connected to the command's standard input when the command starts.
//The pipe will be closed automatically after Wait sees the command exit.
// A caller need only call Close to force the pipe to close sooner.
//For example, if the command being run will not exit until standard input is closed, the caller must close the pipe.
func (c *SSHCommand) StdinPipe() (io.WriteCloser, error) {
	return c.cmd.StdinPipe()
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (c *SSHCommand) Output() ([]byte, error) {
	content, err := c.cmd.Output()
	c.end()
	return content, err
}

// CombinedOutput runs the command and returns its combined standard
// output and standard error.
func (c *SSHCommand) CombinedOutput() ([]byte, error) {
	content, err := c.cmd.CombinedOutput()
	c.end()
	return content, err
}

// Start starts the specified command but does not wait for it to complete.
//
// The Wait method will return the exit code and release associated resources
// once the command exits.
func (c *SSHCommand) Start() error {
	return c.cmd.Start()
}

// Run starts the specified command and waits for it to complete.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
//
// If the command starts but does not complete successfully, the error is of
// type *ExitError. Other error types may be returned for other situations.
func (c *SSHCommand) Run() error {
	err := c.cmd.Run()
	c.end()
	return err
}

func (c *SSHCommand) end() error {
	err1 := c.closeTunnels()
	err2 := os.Remove(c.keyFile.Name())
	if err1 != nil {
		return fmt.Errorf("Unable to close ssh tunnels : %s", err1.Error())
	}
	if err2 != nil {
		return fmt.Errorf("Unable to close ssh tunnels : %s", err2.Error())
	}
	return nil
}

func recCreateTunnels(ssh *SSHConfig, tunnels *[]*sshTunnel) (*sshTunnel, error) {
	if ssh != nil {
		tunnel, err := recCreateTunnels(ssh.GatewayConfig, tunnels)
		if err != nil {
			return nil, err
		}
		cfg := ssh
		if tunnel != nil {
			gateway := *ssh.GatewayConfig
			gateway.Port = tunnel.port
			gateway.Host = "127.0.0.1"
			cfg.GatewayConfig = &gateway
		}
		if cfg.GatewayConfig != nil {
			tunnel, err = createTunnel(cfg)
			if err != nil {
				return nil, err
			}
			*tunnels = append(*tunnels, tunnel)
			return tunnel, err
		}
		return nil, nil
	}
	return nil, nil

}

func (ssh *SSHConfig) createTunnels() ([]*sshTunnel, *SSHConfig, error) {
	var tunnels []*sshTunnel
	tunnel, err := recCreateTunnels(ssh, &tunnels)
	if err != nil {
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to create SSH Tunnels : %s", err.Error())
		}
	}
	sshConfig := *ssh
	if tunnel == nil {
		return nil, &sshConfig, nil
	}

	if ssh.GatewayConfig != nil {
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to create SSH Tunnel : %s", err.Error())
		}
		sshConfig.Port = tunnel.port
		sshConfig.Host = "127.0.0.1"
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, &sshConfig, nil
}

func createSSHCmd(sshConfig *SSHConfig, cmdString string, withSudo bool) (string, *os.File, error) {
	f, err := CreateTempFileFromString(sshConfig.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("Unable to create temporary key file: %s", err.Error())
	}
	//defer os.Remove(f.Name())
	options := "-q -oLogLevel=error -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no"

	sshCmdString := fmt.Sprintf("ssh -i %s %s -p %d %s@%s",
		f.Name(),
		options,
		sshConfig.Port,
		sshConfig.User,
		sshConfig.Host,
	)

	sudoOpt := ""
	if withSudo {
		// tty option is required for some command like ls
		sudoOpt = " -t sudo"
	}

	if cmdString != "" {
		sshCmdString = sshCmdString + fmt.Sprintf("%s bash <<'ENDSSH'\n%s\nENDSSH", sudoOpt, cmdString)
	}
	return sshCmdString, f, nil

}

// Command returns the Cmd struct to execute cmdString remotely
func (ssh *SSHConfig) Command(cmdString string) (*SSHCommand, error) {
	return ssh.command(cmdString, false)
}

// SudoCommand returns the Cmd struct to execute cmdString remotely. Command is executed with sudo
func (ssh *SSHConfig) SudoCommand(cmdString string) (*SSHCommand, error) {
	return ssh.command(cmdString, true)
}

func (ssh *SSHConfig) command(cmdString string, withSudo bool) (*SSHCommand, error) {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		return nil, fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createSSHCmd(sshConfig, cmdString, withSudo)
	if err != nil {
		return nil, fmt.Errorf("Unable to create command : %s", err.Error())
	}
	//log.Println(sshCmdString)
	cmd := exec.Command("bash", "-c", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return &sshCommand, nil
}

// WaitServerReady waits until the SSH server is ready
func (ssh *SSHConfig) WaitServerReady(timeout time.Duration) error {
	err := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			cmd, _ := ssh.Command("whoami")
			return cmd.Run()
		},
		timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to wait SSH ready on server '%s': %s", ssh.Host, err.Error())
	}
	return nil
}

//Copy copy a file/directory from/to local to/from remote
func (ssh *SSHConfig) Copy(remotePath, localPath string, isUpload bool) error {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		return fmt.Errorf("Unable to create tunnels : %s", err.Error())
	}

	identityfile, err := CreateTempFileFromString(sshConfig.PrivateKey)
	if err != nil {
		return fmt.Errorf("Unable to create temporary key file: %s", err.Error())
	}

	cmdTemplate, err := template.New("Command").Parse("scp -i {{.IdentityFile}} -P {{.Port}} {{.Options}} {{if .IsUpload}}{{.LocalPath}} {{.User}}@{{.Host}}:{{.RemotePath}}{{else}}{{.User}}@{{.Host}}:{{.RemotePath}} {{.LocalPath}}{{end}}")
	if err != nil {
		return fmt.Errorf("Error parsing command template: %s", err.Error())
	}

	var copyCommand bytes.Buffer
	if err := cmdTemplate.Execute(&copyCommand, struct {
		IdentityFile string
		Port         int
		Options      string
		User         string
		Host         string
		RemotePath   string
		LocalPath    string
		IsUpload     bool
	}{
		IdentityFile: identityfile.Name(),
		Port:         sshConfig.Port,
		Options:      "-q -oLogLevel=error -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no",
		User:         sshConfig.User,
		Host:         sshConfig.Host,
		RemotePath:   remotePath,
		LocalPath:    localPath,
		IsUpload:     isUpload,
	}); err != nil {
		return fmt.Errorf("Error executing template: %s", err.Error())
	}

	sshCmdString := copyCommand.String()

	cmd := exec.Command("bash", "-c", sshCmdString)
	//log.Println("cmd", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: identityfile,
	}
	return sshCommand.Run()
}

// UploadString uploads a string into a remote file
func (ssh *SSHConfig) UploadString(remotePath, content string) error {
	f, err := CreateTempFileFromString(content)
	if err != nil {
		return err
	}
	err = ssh.Copy(remotePath, f.Name(), true)
	os.Remove(f.Name())
	return err
}

// Exec executes the cmd using ssh
func (ssh *SSHConfig) Exec(cmdString string) error {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createSSHCmd(sshConfig, cmdString, false)
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	bash, err := exec.LookPath("bash")
	//log.Println("BASH ", bash)
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	var args []string
	if cmdString == "" {
		args = []string{sshCmdString}
	} else {
		args = []string{"-c", sshCmdString}
	}
	//log.Println("ARGS ", args)
	err = syscall.Exec(bash, args, nil)
	os.Remove(keyFile.Name())
	return err
}

// Enter Enter to interactive shell
func (ssh *SSHConfig) Enter() error {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createSSHCmd(sshConfig, "", false)
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		for _, t := range tunnels {
			t.Close()
		}
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}

	proc := exec.Command(bash, "-c", sshCmdString)
	proc.Stdout = os.Stdout
	proc.Stdin = os.Stdin
	proc.Stderr = os.Stderr
	err = proc.Run()
	os.Remove(keyFile.Name())
	return err
}

// CommandContext is like Command but includes a context.
//
// The provided context is used to kill the process (by calling
// os.Process.Kill) if the context becomes done before the command
// completes on its own.
func (ssh *SSHConfig) CommandContext(ctx context.Context, cmdString string) (*SSHCommand, error) {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		return nil, fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createSSHCmd(sshConfig, cmdString, false)
	if err != nil {
		return nil, fmt.Errorf("Unable to create command : %s", err.Error())
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return &sshCommand, nil
}

// CreateKeyPair creates a key pair
func CreateKeyPair() (publicKeyBytes []byte, privateKeyBytes []byte, err error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey
	pub, err := ssh.NewPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes = ssh.MarshalAuthorizedKey(pub)

	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBytes = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBytes,
		},
	)
	return publicKeyBytes, privateKeyBytes, nil
}

// ExtractRetCode extracts info from the error
func ExtractRetCode(err error) (string, int, error) {
	retCode := -1
	msg := "__ NO MESSAGE __"
	if ee, ok := err.(*exec.ExitError); ok {
		//Try to get retCode
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			retCode = status.ExitStatus()
		} else {
			return msg, retCode, fmt.Errorf("ExitError.Sys is not a 'syscall.WaitStatus'")
		}
		//Retrive error message
		msg = ee.Error()
		return msg, retCode, nil
	}
	return msg, retCode, fmt.Errorf("Error is not an 'ExitError'")
}

package system

import (
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
	"time"

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
}

//Close close ssh tunnel
func (tunnel *sshTunnel) Close() error {
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

func createKeyFile(content string) (*os.File, error) {
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
	f, err := createKeyFile(cfg.GatewayConfig.PrivateKey)
	if err != nil {
		return nil, err
	}
	//defer os.Remove(f.Name())
	freePort, err := getFreePort()
	if err != nil {
		return nil, err
	}
	options := "-q -oServerAliveInterval=60 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes"
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
	f, err := createKeyFile(sshConfig.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("Unable to create temporary key file: %s", err.Error())
	}
	//defer os.Remove(f.Name())
	options := "-q -oLogLevel=error -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes"

	sshCmdString := fmt.Sprintf("ssh -i %s  %s@%s %s -p %d",
		f.Name(),
		sshConfig.User,
		sshConfig.Host,
		options,
		sshConfig.Port,
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

func createDownloadCmd(sshConfig *SSHConfig, remotePath, localPath string) (string, *os.File, error) {
	f, err := createKeyFile(sshConfig.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("Unable to create temporary key file: %s", err.Error())
	}
	//defer os.Remove(f.Name())
	options := "-q -oLogLevel=error -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes"

	sshCmdString := fmt.Sprintf("scp -i %s -P %d %s %s@%s:%s %s",
		f.Name(),
		sshConfig.Port,
		options,
		sshConfig.User,
		sshConfig.Host,
		remotePath,
		localPath,
	)
	return sshCmdString, f, nil
}

func createUploadCmd(sshConfig *SSHConfig, remotePath, localPath string) (string, *os.File, error) {
	f, err := createKeyFile(sshConfig.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("Unable to create temporary key file: %s", err.Error())
	}
	//defer os.Remove(f.Name())
	options := "-q -oLogLevel=error -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes"

	sshCmdString := fmt.Sprintf("scp -i %s -P %d %s %s %s@%s:%s",
		f.Name(),
		sshConfig.Port,
		options,
		localPath,
		sshConfig.User,
		sshConfig.Host,
		remotePath,
	)
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
	fmt.Println(sshCmdString)
	cmd := exec.Command("bash", "-c", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return &sshCommand, nil
}

//WaitServerReady waits until the SSH server is ready
func (ssh *SSHConfig) WaitServerReady(timeout time.Duration) error {
	c := make(chan bool, 1)
	go func() {
		for {
			cmd, _ := ssh.Command("whoami")
			err := cmd.Run()
			if err == nil {
				c <- true
				return
			}
			time.Sleep(1 * time.Second)
		}

	}()
	select {
	case _ = <-c:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("Timeout")
	}

}

//Download dowloads remotePath into localPath
func (ssh *SSHConfig) Download(remotePath, localPath string) error {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createDownloadCmd(sshConfig, remotePath, localPath)
	if err != nil {
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	cmd := exec.Command("bash", "-c", sshCmdString)
	fmt.Println("cmd", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return sshCommand.Run()
}

//Upload upload localPath into remotePath
func (ssh *SSHConfig) Upload(remotePath, localPath string) error {
	tunnels, sshConfig, err := ssh.createTunnels()
	if err != nil {
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	sshCmdString, keyFile, err := createUploadCmd(sshConfig, remotePath, localPath)
	if err != nil {
		return fmt.Errorf("Unable to create command : %s", err.Error())
	}
	cmd := exec.Command("bash", "-c", sshCmdString)
	fmt.Println("cmd", sshCmdString)
	sshCommand := SSHCommand{
		cmd:     cmd,
		tunnels: tunnels,
		keyFile: keyFile,
	}
	return sshCommand.Run()
}

//Exec executes the cmd using ssh
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
	fmt.Println("BASH ", bash)
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
	return syscall.Exec(bash, args, nil)

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

//CreateKeyPair creates a key pair
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

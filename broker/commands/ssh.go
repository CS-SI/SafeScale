package commands

import (
	"fmt"
	"strings"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
)

// broker ssh connect vm2
// broker ssh run vm2 -c "uname -a"
// broker ssh copy /file/test.txt vm1://tmp
// broker ssh copy vm1:/file/test.txt /tmp

const protocol_separator = ":"

//SSHAPI defines ssh management API
type SSHAPI interface {
	Connect(name string) error
	Run(cmd string) (string, error)
	Copy(from string, to string)
}

//NewSSHService creates a SSH service
func NewSSHService(api api.ClientAPI) *SSHService {
	return &SSHService{
		provider:  providers.FromClient(api),
		vmService: NewVMService(api),
	}
}

//SSHService SSH service
type SSHService struct {
	provider  *providers.Service
	vmService VMAPI
}

//Run execute command on the VM
func (srv *SSHService) Run(vmName, cmd string) (string, error) {
	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return "", fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return "", err
	}

	sshcmd, err := ssh.Command(cmd)
	if err != nil {
		return "", err
	}
	out, err := sshcmd.Output()
	if err != nil {
		return "", err
	}

	return string(out[:]), nil
}

func extractVMName(in string) (string, error) {
	parts := strings.Split(in, protocol_separator)
	if len(parts) == 1 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", fmt.Errorf("Too many parts in path")
	}
	vmName := strings.TrimSpace(parts[0])
	for _, protocol := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(vmName) == protocol {
			return "", fmt.Errorf("No protocol expected. Only VM name")
		}
	}

	return vmName, nil
}

func extractPath(in string) (string, error) {
	parts := strings.Split(in, protocol_separator)
	if len(parts) == 1 {
		return in, nil
	}
	if len(parts) > 2 {
		return "", fmt.Errorf("Too many parts in path")
	}
	_, err := extractVMName(in)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(parts[1]), nil
}

//Copy copy file/directory
func (srv *SSHService) Copy(from, to string) error {
	vmName := ""
	var upload bool
	var localPath, remotePath string
	// Try exctract vm
	vmFrom, err := extractVMName(from)
	if err != nil {
		return err
	}
	vmTo, err := extractVMName(to)
	if err != nil {
		return err
	}

	// Vm checks
	if vmFrom != "" && vmTo != "" {
		return fmt.Errorf("Copy between 2 VM is not supported yet")
	}
	if vmFrom == "" && vmTo == "" {
		return fmt.Errorf("No VM name specified neither in from nor to")
	}

	fromPath, err := extractPath(from)
	if err != nil {
		return err
	}
	toPath, err := extractPath(to)
	if err != nil {
		return err
	}

	if vmFrom != "" {
		vmName = vmFrom
		remotePath = fromPath
		localPath = toPath
		upload = false
	} else {
		vmName = vmTo
		remotePath = toPath
		localPath = fromPath
		upload = true
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return err
	}

	if upload {
		return ssh.Upload(remotePath, localPath)
	}
	return ssh.Download(remotePath, localPath)
}

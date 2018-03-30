package commands

import (
	"fmt"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
)

// broker ssh connect vm2
// broker ssh run vm2 -c "uname -a"
// broker ssh copy /file/test.txt vm1://tmp
// broker ssh copy vm1:/file/test.txt /tmp

//SSHAPI defines ssh management API
type SSHAPI interface {
	Connect(name string) error
	Run(cmd string) (string, error)
	Scp(from string, to string)
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

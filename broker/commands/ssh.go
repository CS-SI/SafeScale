package commands

import (
	"github.com/SafeScale/providers"
)

// broker ssh connect vm2
// broker ssh run vm2 -c "uname -a"
// broker ssh copy /file/test.txt vm1://tmp
// broker ssh copy vm1:/file/test.txt /tmp

//SSHAPI defines ssh management API
type SSHAPI interface {
	Connect(name string) error
	Run(ref string) error
	Scp(from string, to string)
}

// //NewSSHService creates a SSH service
// func NewSSHService(api api.ClientAPI) *SSHService {
// 	return &SSHService{
// 		provider: providers.FromClient(api),
// 		vm:       NewVMService(api),
// 	}
// }

//SSHService SSH service
type SSHService struct {
	provider *providers.Service
	vm       VMAPI
}

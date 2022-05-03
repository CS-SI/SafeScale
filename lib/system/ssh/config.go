package ssh

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Config is a shared interface for both binary-based ssh and library-based ssh
type Config interface {
	CopyWithTimeout(context.Context, string, string, bool, time.Duration) (int, string, string, fail.Error)
	Enter(string, string) fail.Error
	WaitServerReady(context.Context, string, time.Duration) (string, fail.Error)
	GetUser() (string, fail.Error)
	GetHostname() (string, fail.Error)
	GetPort() (uint, fail.Error)
	GetLocalPort() (uint, fail.Error)
	GetIPAddress() (string, fail.Error)
	GetPrivateKey() (string, fail.Error)
	GetPrimaryGatewayConfig() (Config, fail.Error)
	GetSecondaryGatewayConfig() (Config, fail.Error)
	NewCommand(context.Context, string) (*system.SSHCommand, fail.Error)
	NewSudoCommand(context.Context, string) (*system.SSHCommand, fail.Error)
	GetGatewayConfig(uint) (Config, fail.Error)
}

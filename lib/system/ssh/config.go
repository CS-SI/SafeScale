package ssh

import (
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type CommonConfig struct {
	Hostname               string        `json:"hostname"`
	IPAddress              string        `json:"ip_address"`
	Port                   int           `json:"port"`
	User                   string        `json:"user"`
	PrivateKey             string        `json:"private_key"`
	LocalPort              int           `json:"-"`
	LocalHost              string        `json:"local_host"`
	GatewayConfig          sshapi.Config `json:"primary_gateway_config,omitempty"`
	SecondaryGatewayConfig sshapi.Config `json:"secondary_gateway_config,omitempty"`
}

func NewConfig(hostname string, ipAddress string, port int, user string, privateKey string, localPort int, localHost string, gatewayConfig sshapi.Config, secondaryGatewayConfig sshapi.Config) *CommonConfig {
	return &CommonConfig{Hostname: hostname, IPAddress: ipAddress, Port: port, User: user, PrivateKey: privateKey, LocalPort: localPort, LocalHost: localHost, GatewayConfig: gatewayConfig, SecondaryGatewayConfig: secondaryGatewayConfig}
}

func NewConfigFrom(ac sshapi.Config) (*CommonConfig, fail.Error) {
	if valid.IsNil(ac) {
		return nil, fail.InvalidParameterCannotBeNilError("ac")
	}

	hostname, _ := ac.GetHostname()
	IPAddress, _ := ac.GetIPAddress()
	port, _ := ac.GetPort()
	user, _ := ac.GetUser()
	privateKey, _ := ac.GetPrivateKey()
	localPort, _ := ac.GetLocalPort()
	localHost, _ := ac.GetLocalHost()
	gatewayConfig, _ := ac.GetPrimaryGatewayConfig()
	secondaryGatewayConfig, _ := ac.GetSecondaryGatewayConfig()

	return &CommonConfig{Hostname: hostname, IPAddress: IPAddress, Port: int(port), User: user, PrivateKey: privateKey, LocalPort: int(localPort), LocalHost: localHost, GatewayConfig: gatewayConfig, SecondaryGatewayConfig: secondaryGatewayConfig}, nil
}

func (sconf CommonConfig) GetUser() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.User, nil
}

func (sconf CommonConfig) GetHostname() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.Hostname, nil
}

func (sconf CommonConfig) GetLocalHost() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.LocalHost, nil
}

func (sconf CommonConfig) GetPort() (uint, fail.Error) {
	if valid.IsNil(sconf) {
		return 0, fail.InvalidInstanceError()
	}
	return uint(sconf.Port), nil
}

func (sconf CommonConfig) GetLocalPort() (uint, fail.Error) {
	if valid.IsNil(sconf) {
		return 0, fail.InvalidInstanceError()
	}
	return uint(sconf.LocalPort), nil
}

func (sconf CommonConfig) GetIPAddress() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.IPAddress, nil
}

func (sconf CommonConfig) GetPrivateKey() (string, fail.Error) {
	if valid.IsNil(sconf) {
		return "", fail.InvalidInstanceError()
	}
	return sconf.PrivateKey, nil
}

func (sconf CommonConfig) GetPrimaryGatewayConfig() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.GatewayConfig, nil
}

func (sconf CommonConfig) GetSecondaryGatewayConfig() (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}
	return sconf.SecondaryGatewayConfig, nil
}

func (sconf CommonConfig) GetGatewayConfig(num uint) (sshapi.Config, fail.Error) {
	if valid.IsNil(sconf) {
		return nil, fail.InvalidInstanceError()
	}

	switch num {
	case 0:
		return sconf.GatewayConfig, nil
	case 1:
		return sconf.SecondaryGatewayConfig, nil
	default:
		return nil, fail.InvalidParameterError("num", "only can be 0 or 1")
	}
}

func (sconf CommonConfig) HasGateways() (bool, fail.Error) {
	if valid.IsNil(sconf) {
		return false, fail.InvalidInstanceError()
	}

	if sconf.GatewayConfig == nil && sconf.SecondaryGatewayConfig == nil {
		return false, nil
	}

	return true, nil
}

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

package internal

import (
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ConfigProperties describes the internal content of ConfigProperties
type ConfigProperties struct {
	User                   string            `json:"user"`
	IPAddress              string            `json:"ip_address"`
	PrivateKey             string            `json:"private_key"`
	Hostname               string            `json:"hostname"`
	GatewayConfig          *ConfigProperties `json:"primary_gateway_config,omitempty"`
	SecondaryGatewayConfig *ConfigProperties `json:"secondary_gateway_config,omitempty"`
	Port                   uint              `json:"port"`
	LocalPort              uint              `json:"-"`
}

// Clone makes a clone of instance
func (sci *ConfigProperties) Clone() *ConfigProperties {
	if sci == nil {
		return &ConfigProperties{}
	}

	out := *sci
	if sci.GatewayConfig != nil {
		newConf := sci.GatewayConfig.Clone()
		out.GatewayConfig = newConf
	}
	if sci.SecondaryGatewayConfig != nil {
		newConf := sci.SecondaryGatewayConfig.Clone()
		out.SecondaryGatewayConfig = newConf
	}
	return &out
}

// Config contains the properties of a SSH Config
type Config struct {
	_private ConfigProperties
}

// NewEmptyConfig instanciates a sshConfig instance
func NewEmptyConfig() *Config {
	out := &Config{
		_private: ConfigProperties{
			GatewayConfig:          nil,
			SecondaryGatewayConfig: nil,
		},
	}
	return out
}

// NewConfig ...
func NewConfig(hostname, ipAddress string, port uint, user, privateKey string, gws ...api.Config) (*Config, fail.Error) {
	if hostname == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("hostname")
	}
	if ipAddress == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ipAddress")
	}
	if privateKey == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("privateKey")
	}
	if port == 0 {
		port = DefaultPort
	}

	out := NewEmptyConfig()
	out._private.User = user
	out._private.Hostname = hostname
	out._private.IPAddress = ipAddress
	out._private.Port = port
	out._private.PrivateKey = privateKey

	if len(gws) > 0 {
		gw := gws[api.PrimaryGateway]
		if gw != nil {
			xerr := out.SetGatewayConfig(api.PrimaryGateway, gw)
			if xerr != nil {
				return nil, xerr
			}
		}
	}

	if len(gws) > 1 {
		gw := gws[api.SecondaryGateway]
		if gw != nil {
			xerr := out.SetGatewayConfig(api.SecondaryGateway, gw)
			if xerr != nil {
				return nil, xerr
			}
		}
	}

	return out, nil
}

// SetHostname ...
func (conf *Config) SetHostname(hostname string) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if hostname == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostname")
	}

	conf._private.Hostname = hostname
	return nil
}

// SetIPAddress ...
func (conf *Config) SetIPAddress(ipAddress string) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if ipAddress == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ipAddress")
	}

	conf._private.IPAddress = ipAddress
	return nil
}

// SetPort ...
func (conf *Config) SetPort(port uint) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if port == 0 {
		port = 22
	}
	conf._private.Port = port
	return nil
}

// SetLocalPort ...
func (conf *Config) SetLocalPort(port uint) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if port == 0 {
		port = DefaultPort
	}
	conf._private.LocalPort = port
	return nil
}

// SetPrivateKey ...
func (conf *Config) SetPrivateKey(privateKey string) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if privateKey == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("privateKey")
	}

	conf._private.PrivateKey = privateKey
	return nil
}

// SetUser ...
func (conf *Config) SetUser(user string) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if user == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("user")
	}

	conf._private.User = user
	return nil
}

// SetGatewayConfig ...
func (conf *Config) SetGatewayConfig(idx api.WhatGateway, gwConfig api.Config) fail.Error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}
	if idx > 1 {
		return fail.InvalidParameterError("idx", "must be 0 for mprimary gateway or 1 for secondary gateway")
	}

	if gwConfig == nil {
		switch idx {
		case api.PrimaryGateway:
			conf._private.GatewayConfig = nil
		case api.SecondaryGateway:
			conf._private.SecondaryGatewayConfig = nil
		}
		return nil
	}

	newConf := ConfigProperties{
		User:       gwConfig.User(),
		IPAddress:  gwConfig.IPAddress(),
		PrivateKey: gwConfig.PrivateKey(),
		Hostname:   gwConfig.Hostname(),
		Port:       gwConfig.Port(),
		LocalPort:  gwConfig.LocalPort(),
	}
	switch idx {
	case api.PrimaryGateway:
		conf._private.GatewayConfig = &newConf
	case api.SecondaryGateway:
		conf._private.SecondaryGatewayConfig = &newConf
	}

	return nil
}

func (conf Config) MarshalJSON() ([]byte, error) {
	jsoned, err := json.Marshal(conf._private)
	if err != nil {
		return nil, err
	}
	return jsoned, nil
}

func (conf *Config) UnmarshalJSON(in []byte) error {
	// Do not use valid.IsNil() here, the instance may be null value when calling this method
	if conf == nil {
		return fail.InvalidInstanceError()
	}

	err := json.Unmarshal(in, &conf._private)
	if err != nil {
		return err
	}

	return nil
}

// IsNull tells if the instance is a null value
func (conf *Config) IsNull() bool {
	return conf == nil || conf._private.IPAddress == ""
}

// PrivateKey ...
func (conf Config) PrivateKey() string {
	return conf._private.PrivateKey
}

// User ...
func (conf Config) User() string {
	return conf._private.User
}

// Hostname ...
func (conf Config) Hostname() string {
	return conf._private.Hostname
}

// IPAddress ...
func (conf Config) IPAddress() string {
	return conf._private.IPAddress
}

// GatewayConfig ...
func (conf Config) GatewayConfig(idx api.WhatGateway) api.Config {
	if idx > 1 {
		return nil
	}

	var newConf *ConfigProperties
	switch idx {
	case api.PrimaryGateway:
		newConf = conf._private.GatewayConfig.Clone()
	case api.SecondaryGateway:
		newConf = conf._private.SecondaryGatewayConfig.Clone()
	default:
		return nil
	}

	if newConf == nil {
		return NewEmptyConfig()
	}

	return &Config{*newConf}
}

// PrimaryGatewayConfig ...
func (conf Config) PrimaryGatewayConfig() api.Config {
	return conf.GatewayConfig(0)
}

// SecondaryGatewayConfig ...
func (conf Config) SecondaryGatewayConfig() api.Config {
	return conf.GatewayConfig(1)
}

// Port ...
func (conf Config) Port() uint {
	return conf._private.Port
}

// LocalPort ...
func (conf Config) LocalPort() uint {
	return conf._private.LocalPort
}

// Clone returns the configuration
func (conf Config) Clone() api.Config {
	out, _ := NewConfig(conf._private.Hostname, conf._private.IPAddress, conf._private.Port, conf._private.User, conf._private.PrivateKey)
	gw := conf._private.GatewayConfig

	if gw != nil {
		out._private.GatewayConfig = gw.Clone()
	}
	gw = conf._private.SecondaryGatewayConfig
	if gw != nil {
		out._private.SecondaryGatewayConfig = gw.Clone()
	}
	return out
}

// ConvertInternalToApiConfig ...
func ConvertInternalToApiConfig(conf ConfigProperties) *Config {
	out := Config{
		_private: ConfigProperties{
			Hostname:   conf.Hostname,
			IPAddress:  conf.IPAddress,
			Port:       conf.Port,
			User:       conf.User,
			PrivateKey: conf.PrivateKey,
		},
	}
	if conf.GatewayConfig != nil {
		out._private.GatewayConfig = conf.GatewayConfig.Clone()
	}
	if conf.SecondaryGatewayConfig != nil {
		out._private.SecondaryGatewayConfig = conf.SecondaryGatewayConfig.Clone()
	}
	return &out
}

// Properties ...
func (c Config) Properties() *ConfigProperties {
	return c._private.Clone()
}

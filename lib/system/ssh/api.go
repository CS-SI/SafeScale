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
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Config is a shared interface for both binary-based ssh and library-based ssh
type Config interface {
	GetUser() (string, fail.Error)
	GetHostname() (string, fail.Error)
	GetLocalHost() (string, fail.Error)
	GetPort() (uint, fail.Error)
	GetLocalPort() (uint, fail.Error)
	GetIPAddress() (string, fail.Error)
	GetPrivateKey() (string, fail.Error)
	GetPrimaryGatewayConfig() (Config, fail.Error)
	GetSecondaryGatewayConfig() (Config, fail.Error)
	GetGatewayConfig(uint) (Config, fail.Error)
	HasGateways() (bool, fail.Error)
}

// Connector describes the interface that exposes methods to interact with remote
type Connector interface {
	CreatePersistentTunneling() fail.Error
	Config() (Config, fail.Error)
	CopyWithTimeout(context.Context, string, string, bool, time.Duration) (int, string, string, fail.Error)
	Enter(string, string) fail.Error
	NewCommand(context.Context, string) (CommandInterface, fail.Error)
	NewSudoCommand(context.Context, string) (CommandInterface, fail.Error)
	WaitServerReady(context.Context, string, time.Duration) (string, fail.Error)
}

// CommandInterface defines a SSH command
type CommandInterface interface {
	String() string
	Close() fail.Error
	RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error)
}

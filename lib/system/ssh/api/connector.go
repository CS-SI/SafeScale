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

package api

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Connector describes the interface that exposes methods to interact with remote
type Connector interface {
	Config() (Config, fail.Error)
	CopyWithTimeout(context.Context, string, string, bool, time.Duration) (int, string, string, fail.Error)
	Close() fail.Error
	CreatePersistentTunnel() fail.Error
	Enter(string, string) fail.Error
	NewCommand(context.Context, string) (Command, fail.Error)
	NewSudoCommand(context.Context, string) (Command, fail.Error)
	WaitServerReady(context.Context, string, time.Duration) (string, fail.Error)
}

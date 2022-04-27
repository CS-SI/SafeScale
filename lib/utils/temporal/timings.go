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

package temporal

import (
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/pelletier/go-toml/v2"
)

const (
	// DefaultContextTimeout default timeout for grpc command invocation
	defaultContextTimeout = 1 * time.Minute

	// defaultHostOperationTimeout default timeout to handle operations
	defaultHostOperationTimeout = 120 * time.Second

	// defaultHostCreationTimeout timeout for grpc command relative to host creation
	defaultHostCreationTimeout = 8 * time.Minute

	// defaultHostLongOperationTimeout is a Long timeout
	defaultHostLongOperationTimeout = 14 * time.Minute

	// defaultHostCleanupTimeout is the default timeout of host teardown operations
	defaultHostCleanupTimeout = 5 * time.Minute

	// defaultCommunicationTimeout is the default timeout for HTTP communication with Provider
	defaultCommunicationTimeout = 3 * time.Minute

	// defaultMetadataTimeout default timeout to handle object storage issues
	defaultMetadataTimeout = 150 * time.Second

	// defaultOperationTimeout default timeout to handle operations
	defaultOperationTimeout = 150 * time.Second

	// defaultSSHConnectionTimeout is the default ssh timeout connection
	defaultSSHConnectionTimeout = 3 * time.Minute

	// defaultConnectionTimeout is the default connection timeout
	defaultConnectionTimeout = 1 * time.Minute

	// defaultExecutionTimeout is the default linux command operation timeout
	defaultExecutionTimeout = 8 * time.Minute

	// DefaultMetadataReadAfterWriteTimeout is the default timeout applied to validate metadata write is effective
	defaultMetadataReadAfterWriteTimeout = 90 * time.Second

	// defaultSmallDelay is the predefined small delay
	defaultSmallDelay = 1 * time.Second

	// defaultNormalDelay is the default delay
	defaultNormalDelay = 10 * time.Second

	// defaultBigDelay is a big delay
	defaultBigDelay = 30 * time.Second
)

//go:generate minimock -o mocks/mock_timings.go -i github.com/CS-SI/SafeScale/v22/lib/utils/temporal.Timings

type Timings interface {
	// OperationTimeout ...
	OperationTimeout() time.Duration

	// HostOperationTimeout ...
	HostOperationTimeout() time.Duration

	// HostLongOperationTimeout ...
	HostLongOperationTimeout() time.Duration

	// HostCreationTimeout ...
	HostCreationTimeout() time.Duration

	// HostCleanupTimeout ...
	HostCleanupTimeout() time.Duration

	// CommunicationTimeout ...
	CommunicationTimeout() time.Duration

	// ConnectionTimeout ...
	ConnectionTimeout() time.Duration

	// ContextTimeout ...
	ContextTimeout() time.Duration

	// ExecutionTimeout ...
	ExecutionTimeout() time.Duration

	// SSHConnectionTimeout ...
	SSHConnectionTimeout() time.Duration

	// MetadataTimeout ...
	MetadataTimeout() time.Duration

	// MetadataReadAfterWriteTimeout ...
	MetadataReadAfterWriteTimeout() time.Duration

	// SmallDelay ...
	SmallDelay() time.Duration
	// NormalDelay returns the currently configure normal delay stored in Timings
	NormalDelay() time.Duration
	// BigDelay returns the currently configured big delay stored in Timings
	BigDelay() time.Duration
}

type Timeouts struct {
	Communication          time.Duration `json:"timeout_communication,omitempty" mapstructure:"communication"`
	Connection             time.Duration `json:"timeout_connection,omitempty" mapstructure:"connection"`
	Context                time.Duration `json:"timeout_context,omitempty" mapstructure:"context"`
	HostCreation           time.Duration `json:"timeout_host_creation,omitempty" mapstructure:"hostcreation"`
	HostCleanup            time.Duration `json:"timeout_host_cleanup,omitempty" mapstructure:"hostcleanup"`
	HostOperation          time.Duration `json:"timeout_host_operation,omitempty" mapstructure:"hostoperation"`
	HostLongOperation      time.Duration `json:"timeout_host_long_operation,omitempty" mapstructure:"hostlongoperation"`
	Operation              time.Duration `json:"timeout_operation,omitempty" mapstructure:"operation"`
	SSHConnection          time.Duration `json:"timeout_ssh_connection,omitempty" mapstructure:"sshconnection"`
	Metadata               time.Duration `json:"timeout_metadata,omitempty" mapstructure:"metadata"`
	MetadataReadAfterWrite time.Duration `json:"timeout_metadata_raw,omitempty" mapstructure:"metadatareadafterwrite"`
}

type Delays struct {
	Small  time.Duration `json:"delay_small,omitempty" mapstructure:"small"`
	Normal time.Duration `json:"delay_normal,omitempty" mapstructure:"normal"`
	Big    time.Duration `json:"delay_big,omitempty" mapstructure:"big"`
}

type MutableTimings struct {
	Timeouts `json:"timeouts" mapstructure:"timeouts"`
	Delays   `json:"delays" mapstructure:"delays"`
}

// NewTimings creates a new instance of MutableTimings with default values
func NewTimings() *MutableTimings {
	return &MutableTimings{
		Timeouts: Timeouts{
			Communication:          CommunicationTimeout(),
			Connection:             ConnectionTimeout(),
			Context:                ContextTimeout(),
			HostCreation:           HostCreationTimeout(),
			HostCleanup:            HostCleanupTimeout(),
			HostOperation:          HostOperationTimeout(),
			HostLongOperation:      HostLongOperationTimeout(),
			Operation:              OperationTimeout(),
			Metadata:               MetadataTimeout(),
			MetadataReadAfterWrite: MetadataReadAfterWriteTimeout(),
			SSHConnection:          SSHConnectionTimeout(),
		},
		Delays: Delays{
			Small:  SmallDelay(),
			Normal: NormalDelay(),
			Big:    BigDelay(),
		},
	}
}

func (t *MutableTimings) Update(a *MutableTimings) error {
	if t == nil {
		return fail.InvalidInstanceError()
	}

	if a == nil {
		return nil
	}

	if t.Communication == 0 && a.Communication != 0 {
		t.Communication = a.Communication
	}
	if t.Connection == 0 && a.Connection != 0 {
		t.Connection = a.Connection
	}
	if t.Context == 0 && a.Context != 0 {
		t.Context = a.Context
	}
	if t.HostCleanup == 0 && a.HostCleanup != 0 {
		t.HostCleanup = a.HostCleanup
	}
	if t.HostCreation == 0 && a.HostCreation != 0 {
		t.HostCreation = a.HostCreation
	}
	if t.HostLongOperation == 0 && a.HostLongOperation != 0 {
		t.HostLongOperation = a.HostLongOperation
	}
	if t.HostOperation == 0 && a.HostOperation != 0 {
		t.HostOperation = a.HostOperation
	}
	if t.Metadata == 0 && a.Metadata != 0 {
		t.Metadata = a.Metadata
	}
	if t.MetadataReadAfterWrite == 0 && a.MetadataReadAfterWrite != 0 {
		t.MetadataReadAfterWrite = a.MetadataReadAfterWrite
	}
	if t.Operation == 0 && a.Operation != 0 {
		t.Operation = a.Operation
	}
	if t.Small == 0 && a.Small != 0 {
		t.Small = a.Small
	}
	if t.Normal == 0 && a.Normal != 0 {
		t.Normal = a.Normal
	}
	if t.Big == 0 && a.Big != 0 {
		t.Big = a.Big
	}

	return nil
}

// ContextTimeout returns the configured timeout for context (optionally overloaded from ENV)
func (t *MutableTimings) ContextTimeout() time.Duration {
	if t == nil {
		return ContextTimeout()
	}

	return t.Timeouts.Context
}

func (t MutableTimings) ToToml() (string, error) {
	barr, err := toml.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(barr), nil
}

// ConnectionTimeout returns the configured timeout for connection
func (t *MutableTimings) ConnectionTimeout() time.Duration {
	if t == nil {
		return ConnectionTimeout()
	}

	return t.Timeouts.Connection
}

// ExecutionTimeout returns the configured timeout for execution
func (t *MutableTimings) ExecutionTimeout() time.Duration {
	if t == nil {
		return ExecutionTimeout()
	}

	return t.Timeouts.Operation
}

// OperationTimeout returns the configured timeout for operation (optionally overloaded from ENV)
func (t *MutableTimings) OperationTimeout() time.Duration {
	if t == nil {
		return OperationTimeout()
	}

	return t.Timeouts.Operation
}

// HostCreationTimeout returns the configured timeout for host creation (optionally overloaded from ENV)
func (t *MutableTimings) HostCreationTimeout() time.Duration {
	if t == nil {
		return HostCreationTimeout()
	}

	return t.Timeouts.HostCreation
}

// HostCleanupTimeout returns the configured timeout for host cleanup
func (t *MutableTimings) HostCleanupTimeout() time.Duration {
	if t == nil {
		return HostCleanupTimeout()
	}

	return t.Timeouts.HostCleanup
}

// HostOperationTimeout returns the configured timeout for host operation (other than creation or cleanup)
func (t *MutableTimings) HostOperationTimeout() time.Duration {
	if t == nil {
		return HostOperationTimeout()
	}

	return t.Timeouts.HostOperation
}

// CommunicationTimeout returns the configured timeout for communication (optionally overloaded from ENV)
func (t *MutableTimings) CommunicationTimeout() time.Duration {
	if t == nil {
		return CommunicationTimeout()
	}

	return t.Timeouts.Communication
}

// HostLongOperationTimeout returns the configured timeout for long Host operation (optionally overloaded from ENV)
func (t *MutableTimings) HostLongOperationTimeout() time.Duration {
	if t == nil {
		return HostLongOperationTimeout()
	}

	return t.Timeouts.HostLongOperation
}

// SSHConnectionTimeout returns the configured timeout for SSH connection
func (t *MutableTimings) SSHConnectionTimeout() time.Duration {
	if t == nil {
		return SSHConnectionTimeout()
	}

	return t.Timeouts.SSHConnection
}

// MetadataTimeout returns the configured timeout for metadata access
func (t *MutableTimings) MetadataTimeout() time.Duration {
	if t == nil {
		return MetadataTimeout()
	}

	return t.Timeouts.Metadata
}

// MetadataReadAfterWriteTimeout returns the configured timeout for metadata read after write
func (t *MutableTimings) MetadataReadAfterWriteTimeout() time.Duration {
	if t == nil {
		return MetadataReadAfterWriteTimeout()
	}

	return t.Timeouts.MetadataReadAfterWrite
}

// SmallDelay returns the duration of a small delay
func (t *MutableTimings) SmallDelay() time.Duration {
	if t == nil {
		return SmallDelay()
	}

	return t.Delays.Small
}

// NormalDelay returns the duration of a normal delay
func (t *MutableTimings) NormalDelay() time.Duration {
	if t == nil {
		return NormalDelay()
	}

	return t.Delays.Normal
}

// BigDelay returns the duration of a big delay
func (t *MutableTimings) BigDelay() time.Duration {
	if t == nil {
		return BigDelay()
	}

	return t.Delays.Big
}

// CommunicationTimeout ...
func CommunicationTimeout() time.Duration {
	return getFromEnv(defaultCommunicationTimeout, "SAFESCALE_COMMUNICATION_TIMEOUT")
}

// MetadataReadAfterWriteTimeout ...
func MetadataReadAfterWriteTimeout() time.Duration {
	return getFromEnv(defaultMetadataReadAfterWriteTimeout, "SAFESCALE_METADATA_READ_AFTER_WRITE_TIMEOUT")
}

// HostLongOperationTimeout ...
func HostLongOperationTimeout() time.Duration {
	return getFromEnv(defaultHostLongOperationTimeout, "SAFESCALE_HOST_LONG_OPERATION_TIMEOUT")
}

// ContextTimeout ...
func ContextTimeout() time.Duration {
	return getFromEnv(defaultContextTimeout, "SAFESCALE_CONTEXT_TIMEOUT")
}

// MetadataTimeout ...
func MetadataTimeout() time.Duration {
	return getFromEnv(defaultMetadataTimeout, "SAFESCALE_METADATA_TIMEOUT")
}

// HostOperationTimeout ...
func HostOperationTimeout() time.Duration {
	return getFromEnv(defaultHostOperationTimeout, "SAFESCALE_HOST_TIMEOUT")
}

// OperationTimeout ...
func OperationTimeout() time.Duration {
	return getFromEnv(defaultOperationTimeout, "SAFESCALE_OP_TIMEOUT", "SAFESCALE_OPERATION_TIMEOUT")
}

// HostCreationTimeout ...
func HostCreationTimeout() time.Duration {
	return getFromEnv(defaultHostCreationTimeout, "SAFESCALE_HOST_CREATION_TIMEOUT")
}

// HostCleanupTimeout ...
func HostCleanupTimeout() time.Duration {
	return getFromEnv(defaultHostCleanupTimeout, "SAFESCALE_HOST_CLEANUP_TIMEOUT")
}

// SSHConnectionTimeout ...
func SSHConnectionTimeout() time.Duration {
	return getFromEnv(defaultSSHConnectionTimeout, "SAFESCALE_SSH_CONNECTION_TIMEOUT", "SAFESCALE_SSH_CONNECT_TIMEOUT")
}

// ConnectionTimeout ...
func ConnectionTimeout() time.Duration {
	return getFromEnv(defaultConnectionTimeout, "SAFESCALE_CONNECTION_TIMEOUT", "SAFESCALE_CONNECT_TIMEOUT")
}

// ExecutionTimeout ...
func ExecutionTimeout() time.Duration {
	return getFromEnv(defaultExecutionTimeout, "SAFESCALE_EXECUTION_TIMEOUT")
}

// MinDelay ...
func MinDelay() time.Duration {
	return getFromEnv(defaultSmallDelay, "SAFESCALE_MIN_DELAY", "SAFESCALE_SMALL_DELAY")
}

// SmallDelay is a synonym for MinDelay
func SmallDelay() time.Duration {
	return MinDelay()
}

// NormalDelay returns the duration for a normal delay
func NormalDelay() time.Duration {
	return getFromEnv(defaultNormalDelay, "SAFESCALE_DEFAULT_DELAY", "SAFESCALE_NORMAL_DELAY")
}

// DefaultDelay is a synonym for NormalDelay
func DefaultDelay() time.Duration {
	return NormalDelay()
}

// BigDelay returns the duration for a big delay
func BigDelay() time.Duration {
	return getFromEnv(defaultBigDelay, "SAFESCALE_BIG_DELAY")
}

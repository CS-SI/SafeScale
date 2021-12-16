/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package stacks

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultContextTimeout default timeout for grpc command invocation
	defaultContextTimeout = 1 * time.Minute

	// DefaultOperationTimeout default timeout to handle operations
	defaultOperationTimeout = 120 * time.Second

	// defaultHostCreationTimeout timeout for grpc command relative to host creation
	defaultHostCreationTimeout = 6 * time.Minute

	// ongHostOperationTimeout is a Long timeout
	defaultLongHostOperationTimeout = 14 * time.Minute

	// defaultHostCleanupTimeout is the default timeout of host teardown operations
	defaultHostCleanupTimeout = 5 * time.Minute

	// defaultCommunicationTimeout is the default timeout for HTTP communication with Provider
	defaultCommunicationTimeout = 3 * time.Minute
)

type Timeouts struct {
	Communication     time.Duration
	Context           time.Duration
	HostCreation      time.Duration
	HostCleanup       time.Duration
	LongHostOperation time.Duration
	Operation         time.Duration
}

// NewTimeouts creates a new instance of Timeouts with default values
func NewTimeouts() Timeouts {
	return Timeouts{
		Context:           defaultContextTimeout,
		Operation:         defaultOperationTimeout,
		HostCreation:      defaultHostCreationTimeout,
		HostCleanup:       defaultHostCleanupTimeout,
		Communication:     defaultCommunicationTimeout,
		LongHostOperation: defaultLongHostOperationTimeout,
	}
}

// ContextTimeout returns the configured timeout for context (optionally overloaded from ENV)
func (t Timeouts) ContextTimeout() time.Duration {
	return GetTimeoutFromEnv(t.Context, "SAFESCALE_CONTEXT_TIMEOUT")
}

// OperationTimeout returns the configured timeout for operation (optionally overloaded from ENV)
func (t Timeouts) OperationTimeout() time.Duration {
	return GetTimeoutFromEnv(t.Operation, "SAFESCALE_OP_TIMEOUT", "SAFESCALE_OPERATION_TIMEOUT")
}

// HostCreationTimeout returns the configured timeout for host creation (optionally overloaded from ENV)
func (t Timeouts) HostCreationTimeout() time.Duration {
	return GetTimeoutFromEnv(t.HostCreation, "SAFESCALE_HOST_CREATION_TIMEOUT")
}

// HostCleanupTimeout returns the configured timeout for host cleanup (optionally overloaded from ENV)
func (t Timeouts) HostCleanupTimeout() time.Duration {
	return GetTimeoutFromEnv(t.HostCleanup, "SAFESCALE_HOST_CLEANUP_TIMEOUT")
}

// CommunicationTimeout returns the configured timeout for communication (optionally overloaded from ENV)
func (t Timeouts) CommunicationTimeout() time.Duration {
	return GetTimeoutFromEnv(t.Communication, "SAFESCALE_COMMUNICATION_TIMEOUT")
}

// LongHostOperationTimeout returns the configured timeout for long Host operation (optionally overloaded from ENV)
func (t Timeouts) LongHostOperationTimeout() time.Duration {
	return GetTimeoutFromEnv(t.LongHostOperation, "SAFESCALE_HOST_LONG_OPERATION_TIMEOUT")
}

type Delays struct {
	Small  time.Duration
	Normal time.Duration
	Big    time.Duration
}

const (
	// smallDelay is the predefined small delay
	smallDelay = 1 * time.Second

	// normalDelay is the default delay
	normalDelay = 5 * time.Second

	// bigDelay is a big delay
	bigDelay = 30 * time.Second
)

// NewDelays creates a new instance of Delays with default values
func NewDelays() Delays {
	return Delays{
		Small:  smallDelay,
		Normal: normalDelay,
		Big:    bigDelay,
	}
}

func (d Delays) SmallDelay() time.Duration {
	return GetTimeoutFromEnv(d.Small, "SAFESCALE_MIN_DELAY", "SAFESCALE_SMALL_DELAY")
}

func (d Delays) NormalDelay() time.Duration {
	return GetTimeoutFromEnv(d.Normal, "SAFESCALE_DEFAULT_DELAY", "SAFESCALE_NORMAL_DELAY")
}

func (d Delays) BigDelay() time.Duration {
	return GetTimeoutFromEnv(d.Big, "SAFESCALE_BIG_DELAY")
}

// GetTimeoutFromEnv reads a environment variable 'string', interprets the variable as a time.Duration if possible and returns the time to the caller
// if there is a failure, it returns a default duration 'duration' passed as an argument when calling the function
func GetTimeoutFromEnv(fallbackDuration time.Duration, keys ...string) time.Duration {
	for _, key := range keys {
		if defaultTimeoutCandidate := os.Getenv(key); defaultTimeoutCandidate != "" {
			newTimeout, err := time.ParseDuration(defaultTimeoutCandidate)
			if err != nil {
				logrus.Warnf("Error parsing variable: [%s]", key)
				continue
			}
			return newTimeout
		}
	}

	return fallbackDuration
}

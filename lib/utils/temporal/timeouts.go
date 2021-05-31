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

package temporal

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultContextTimeout default timeout for grpc command invocation
	DefaultContextTimeout = 1 * time.Minute

	// MetadataTimeout default timeout to handle object storage issues
	DefaultMetadataTimeout = 150 * time.Second

	DefaultOperationTimeout = 120 * time.Second

	// HostTimeout timeout for grpc command relative to host creation
	HostTimeout = 6 * time.Minute

	// LongHostOperationTimeout is a Long timeout
	LongHostOperationTimeout = 14 * time.Minute

	// DefaultSSHConnectionTimeout is the default ssh timeout connection
	DefaultSSHConnectionTimeout = 3 * time.Minute

	// HostCleanupTimeout is the default timeout of host teardown operations
	HostCleanupTimeout = 5 * time.Minute

	// DefaultConnectionTimeout is the default connection timeout
	DefaultConnectionTimeout = 1 * time.Minute

	// defaultCommunicationTimeout is the default timeout for HTTP communication with Provider
	defaultCommunicationTimeout = 3 * time.Minute

	// DefaultExecutionTimeout is the default linux command operation timeout
	DefaultExecutionTimeout = 6 * time.Minute

	// DefaultMetadataReadAfterWriteTimeout is the default timeout applied to validate metadata write is effective
	DefaultMetadataReadAfterWriteTimeout = 90 * time.Second

	// SmallDelay is the predefined small delay
	SmallDelay = 1 * time.Second

	// DefaultDelay is the default delay
	DefaultDelay = 5 * time.Second

	// BigDelay is a big delay
	BigDelay = 30 * time.Second
)

// GetTimeoutFromEnv reads a environment variable 'string', interprets the variable as a time.Duration if possible and returns the time to the caller
// if there is a failure, it returns a default duration 'duration' passed as an argument when calling the function
func GetTimeoutFromEnv(key string, duration time.Duration) time.Duration {
	defaultTimeout := duration

	if defaultTimeoutCandidate := os.Getenv(key); defaultTimeoutCandidate != "" {
		newTimeout, err := time.ParseDuration(defaultTimeoutCandidate)
		if err != nil {
			logrus.Warnf("Error parsing variable: [%s]", key)
			return defaultTimeout
		}
		return newTimeout
	}

	return defaultTimeout
}

// GetMinDelay ...
func GetMinDelay() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_MIN_DELAY", SmallDelay)
}

// GetDefaultDelay ...
func GetDefaultDelay() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_DEFAULT_DELAY", DefaultDelay)
}

// GetBigDelay ...
func GetBigDelay() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_BIG_DELAY", BigDelay)
}

// GetContextTimeout ...
func GetContextTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_CONTEXT_TIMEOUT", DefaultContextTimeout)
}

// GetContextTimeout ...
func GetMetadataTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_METADATA_TIMEOUT", DefaultMetadataTimeout)
}

// GetHostTimeout ...
func GetHostTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_TIMEOUT", HostTimeout)
}

func GetOperationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_OP_TIMEOUT", DefaultOperationTimeout)
}

// GetHostCreationTimeout ...
func GetHostCreationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_CREATION_TIMEOUT", HostTimeout)
}

// GetHostCleanupTimeout ...
func GetHostCleanupTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_CLEANUP_TIMEOUT", HostCleanupTimeout)
}

// GetConnectSSHTimeout ...
func GetConnectSSHTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_SSH_CONNECT_TIMEOUT", DefaultSSHConnectionTimeout)
}

// GetConnectionTimeout ...
func GetConnectionTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_CONNECT_TIMEOUT", DefaultConnectionTimeout)
}

// GetExecutionTimeout ...
func GetExecutionTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_EXECUTION_TIMEOUT", DefaultExecutionTimeout)
}

func MaxTimeout(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// GetCommunicationTimeout ...
func GetCommunicationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_COMMUNICATION_TIMEOUT", defaultCommunicationTimeout)
}

// GetMetadataReadAfterWriteTimeout ...
func GetMetadataReadAfterWriteTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_METADATA_READ_AFTER_WRITE_TIMEOUT", DefaultMetadataReadAfterWriteTimeout)
}

// GetLongOperationTimeout ...
func GetLongOperationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_LONG_OPERATION_TIMEOUT", LongHostOperationTimeout)
}

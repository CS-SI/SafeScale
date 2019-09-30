package utils

import (
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

const (
	// DefaultContextTimeout default timeout for grpc command invocation
	DefaultContextTimeout = 1 * time.Minute

	// HostTimeout timeout for grpc command relative to host creation
	HostTimeout = 5 * time.Minute

	// LongHostOperationTimeout is a Long timeout
	LongHostOperationTimeout = 10 * time.Minute

	// DefaultSSHConnectionTimeout is the default ssh timeout connection
	DefaultSSHConnectionTimeout = 2 * time.Minute

	// HostCleanupTimeout is the default timeout of host teardown operations
	HostCleanupTimeout = 3 * time.Minute

	// DefaultConnectionTimeout is the default connection timeout
	DefaultConnectionTimeout = 30 * time.Second

	// DefaultExecutionTimeout is the default linux command operation timeout
	DefaultExecutionTimeout = 5 * time.Minute

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

// GetHostTimeout ...
func GetHostTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_TIMEOUT", HostTimeout)
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

// GetLongOperationTimeout ...
func GetLongOperationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_LONG_OPERATION_TIMEOUT", LongHostOperationTimeout)
}

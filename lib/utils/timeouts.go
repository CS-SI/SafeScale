package utils

import (
	"os"
	"time"
)

const (
	// DefaultContextTimeout default timeout for grpc command invocation
	DefaultContextTimeout = 1 * time.Minute
	// HostTimeout timeout for grpc command relative to host creation
	HostTimeout = 5 * time.Minute

	// LongHostOperationTimeout = Long timeout
	LongHostOperationTimeout = 10 * time.Minute
	// DefaultSSHConnectionTimeout ...
	DefaultSSHConnectionTimeout = 2 * time.Minute
	// HostCleanupTimeout ...
	HostCleanupTimeout = 3 * time.Minute
	// DefaultConnectionTimeout ...
	DefaultConnectionTimeout = 30 * time.Second
	// DefaultExecutionTimeout ...
	DefaultExecutionTimeout = 5 * time.Minute

	// SmallDelay ...
	SmallDelay = 1 * time.Second
	// DefaultDelay ...
	DefaultDelay = 5 * time.Second
	// BigDelay ...
	BigDelay = 30 * time.Second
)

// GetTimeoutFromEnv ...
func GetTimeoutFromEnv(key string, duration time.Duration) time.Duration {
	defaultTimeout := duration

	if defaultTimeoutCandidate := os.Getenv(key); defaultTimeoutCandidate != "" {
		newTimeout, err := time.ParseDuration(defaultTimeoutCandidate)
		if err != nil {
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

// GetHostCleanupTimeout ...
func GetHostCleanupTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_CLEANUP_TIMEOUT", HostCleanupTimeout)
}

// GetConnectSSHTimeout ...
func GetConnectSSHTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_SSH_CONNECT_TIMEOUT", DefaultSSHConnectionTimeout)
}

// GetLongOperationTimeout ...
func GetLongOperationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_LONG_OPERATION_TIMEOUT", LongHostOperationTimeout)
}

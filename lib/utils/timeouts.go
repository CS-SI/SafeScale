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

	// Long timeout
	LongHostOperationTimeout = 10 * time.Minute

	DefaultSSHConnectionTimeout = 2 * time.Minute
	HostCleanupTimeout          = 3 * time.Minute

	DefaultConnectionTimeout = 30 * time.Second
	DefaultExecutionTimeout  = 5 * time.Minute

	SmallDelay   = 1 * time.Second
	DefaultDelay = 5 * time.Second
	BigDelay     = 30 * time.Second
)

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

func GetMinDelay() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_MIN_DELAY", SmallDelay)
}

func GetDefaultDelay() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_DEFAULT_DELAY", DefaultDelay)
}

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

func GetHostCreationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_CREATION_TIMEOUT", HostTimeout)
}

func GetHostCleanupTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_CLEANUP_TIMEOUT", HostCleanupTimeout)
}

func GetConnectSSHTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_SSH_CONNECT_TIMEOUT", DefaultSSHConnectionTimeout)
}

func GetConnectionTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_CONNECT_TIMEOUT", DefaultConnectionTimeout)
}

func GetExecutionTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_EXECUTION_TIMEOUT", DefaultExecutionTimeout)
}

// GetHostTimeout ...
func GetLongOperationTimeout() time.Duration {
	return GetTimeoutFromEnv("SAFESCALE_HOST_LONG_OPERATION_TIMEOUT", LongHostOperationTimeout)
}

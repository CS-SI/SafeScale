package temporal

import (
	"testing"
	"time"
)

func TestGetBigDelay(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetBigDelay(); got != tt.want {
				t.Errorf("GetBigDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetConnectSSHTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetConnectSSHTimeout(); got != tt.want {
				t.Errorf("GetConnectSSHTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetConnectionTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetConnectionTimeout(); got != tt.want {
				t.Errorf("GetConnectionTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetContextTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetContextTimeout(); got != tt.want {
				t.Errorf("GetContextTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDefaultDelay(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetDefaultDelay(); got != tt.want {
				t.Errorf("GetDefaultDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetExecutionTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetExecutionTimeout(); got != tt.want {
				t.Errorf("GetExecutionTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHostCleanupTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHostCleanupTimeout(); got != tt.want {
				t.Errorf("GetHostCleanupTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHostCreationTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHostCreationTimeout(); got != tt.want {
				t.Errorf("GetHostCreationTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHostTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHostTimeout(); got != tt.want {
				t.Errorf("GetHostTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLongOperationTimeout(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLongOperationTimeout(); got != tt.want {
				t.Errorf("GetLongOperationTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMinDelay(t *testing.T) {
	tests := []struct {
		name string
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMinDelay(); got != tt.want {
				t.Errorf("GetMinDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTimeoutFromEnv(t *testing.T) {
	type args struct {
		key      string
		duration time.Duration
	}
	tests := []struct {
		name string
		args args
		want time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetTimeoutFromEnv(tt.args.key, tt.args.duration); got != tt.want {
				t.Errorf("GetTimeoutFromEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

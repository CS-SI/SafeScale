package integration_tests

import (
	"os"
	"os/exec"
	"strings"
)

//HostInfo ...
type HostInfo struct {
	ID         string
	Name       string
	CPU        int
	RAM        int
	Disk       int
	PUBLIC_IP  string
	PRIVATE_IP string
	State      int
	PrivateKey string
}

//IsSafescaledLaunched ...
func IsSafescaledLaunched() (bool, error) {
	cmd := "ps -ef | grep safescaled | grep -v grep"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "safescaled"), nil
}

//CanBeRun ...
func CanBeRun(command string) (bool, error) {
	cmd := "which " + command
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), command), nil
}

//GetOutput ...
func GetOutput(command string) (string, error) {
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

//RunOnlyInIntegrationTest ...
func RunOnlyInIntegrationTest(key string) {
	if tenant_override := os.Getenv(key); tenant_override == "" {
		panic("This only runs as an integration test")
	}
}

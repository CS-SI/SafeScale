package integration_tests

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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
func GetTaggedOutput(command string, tag string) (string, error) {
	fmt.Printf("%sRunning [%s]\n", tag, command)
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

//GetOutput ...
func GetOutput(command string) (string, error) {
	t := time.Now()
	formatted := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())

	fmt.Printf("[%s] Running [%s]\n", formatted, command)
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

//RunOnlyInIntegrationTest ...
func RunOnlyInIntegrationTest(key string) error {
	if tenantOverride := os.Getenv(key); tenantOverride == "" {
		return fmt.Errorf("this only runs as an integration test")
	}
	return nil
}

package integration_tests

import (
	"errors"
	"log"
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

//IsBrokerdLaunched ...
func IsBrokerdLaunched() (bool, error) {
	cmd := "ps -ef | grep brokerd | grep -v grep"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "brokerd"), nil
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

	if strings.Contains(strings.ToUpper(string(out)), strings.ToUpper("Error")) {
		return string(out), errors.New(string(out))
	}

	return string(out), nil
}

//RunOnlyInIntegrationTest ...
func RunOnlyInIntegrationTest(key string) {
	if tenant_override := os.Getenv(key); tenant_override == "" {
		panic("This only runs as an integration test")
	}
}

//TearDown ...
func TearDown() {
	log.Printf("Starting cleanup...")
	_, _ = GetOutput("broker volume detach volumetest easyvm")
	_, _ = GetOutput("broker volume delete volumetest")
	_, _ = GetOutput("broker host delete easyvm")
	_, _ = GetOutput("broker host delete complexvm")
	_, _ = GetOutput("broker nas delete bnastest")
	_, _ = GetOutput("broker host delete easyvm")
	_, _ = GetOutput("broker host delete complexvm")
	_, _ = GetOutput("broker network delete crazy")
	log.Printf("Finishing cleanup...")
}

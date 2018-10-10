package main

import (
	"errors"
	"os/exec"
	"strings"
)

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

func isBrokerdLaunched() (bool, error) {
	cmd := "ps -ef | grep brokerd | grep -v grep"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "brokerd"), nil
}

func canBeRun(command string) (bool, error) {
	cmd := "which " + command
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), command), nil
}

func getOutput(command string) (string, error) {
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		return "", err
	}

	if strings.Contains(strings.ToUpper(string(out)), strings.ToUpper("Error")) {
		return string(out), errors.New(string(out))
	}

	return string(out), nil
}

func tearDown() {
	_, _ = getOutput("broker volume delete volumetest")
	_, _ = getOutput("broker host delete easyvm")
	_, _ = getOutput("broker host delete complexvm")
	_, _ = getOutput("broker host delete gw-easy")
	_, _ = getOutput("broker network delete easy")
}
/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package integrationtests

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HostInfo ...
type HostInfo struct {
	ID         string
	Name       string
	CPU        int
	RAM        int
	Disk       int
	PublicIP   string
	PrivateIP  string
	State      int
	PrivateKey string
}

// IsSafescaledLaunched ...
func IsSafescaledLaunched() (bool, error) {
	cmd := "ps -ef | grep safescaled | grep -v grep"
	proc := exec.Command("bash", "-c", cmd)
	proc.SysProcAttr = getSyscallAttrs()
	out, err := proc.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "safescaled"), nil
}

// CanBeRun ...
func CanBeRun(command string) (bool, error) {
	cmd := "which " + command
	proc := exec.Command("bash", "-c", cmd)
	proc.SysProcAttr = getSyscallAttrs()
	out, err := proc.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), command), nil
}

// GetTaggedOutput ...
func GetTaggedOutput(command string, tag string) (string, error) {
	fmt.Printf("%sRunning [%s]\n", tag, command)
	proc := exec.Command("bash", "-c", command)
	proc.SysProcAttr = getSyscallAttrs()
	out, err := proc.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

// GetOutput ...
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

// RunOnlyInIntegrationTest ...
func RunOnlyInIntegrationTest(key string) error {
	if tenantOverride := os.Getenv(key); tenantOverride == "" {
		return fmt.Errorf("this only runs as an integration test")
	}
	return nil
}

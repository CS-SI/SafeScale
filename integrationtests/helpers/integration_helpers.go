//go:build allintegration || integration
// +build allintegration integration

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

package helpers

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/integrationtests/providers"
	"github.com/itchyny/gojq"
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

// JSONToMap converts a slice of byte containing JSON code to a map
func JSONToMap(in string) (map[string]interface{}, error) {
	jsoned, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	var out map[string]interface{}
	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func ExtractResult(in string) ([]map[string]interface{}, error) {
	jsoned, err := JSONToMap(in)
	if err != nil {
		return nil, err
	}

	return jsoned["result"].([]map[string]interface{}), nil
}

// RunOnlyInIntegrationTest ...
func RunOnlyInIntegrationTest(key string) error {
	tenantOverride := os.Getenv(key)
	if tenantOverride == "" {
		return fmt.Errorf("failed to find an environment variable %s; this is mandatory to run integration tests", key)
	}

	return nil
}

func RunJq(input string, query string) (string, error) {
	jqQuery, err := gojq.Parse(".result.provider")
	if err != nil {
		return "", err
	}
	var thing map[string]interface{}
	err = json.Unmarshal([]byte(input), &thing)
	if err != nil {
		return "", err
	}
	iter := jqQuery.Run(thing)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return "", err
		}
		return v.(string), nil
	}
	return "", fmt.Errorf("no match")
}

func Setup() bool {
	safescaledLaunched, err := IsSafescaledLaunched()
	if err != nil {
		fmt.Printf("safescaled is not running: %v\n", err)
		return false
	}
	if !safescaledLaunched {
		fmt.Println("This requires that you launch safescaled in background and set the tenant")
		return false
	}

	_, err = CanBeRun("safescale")
	if err != nil {
		fmt.Printf("Cannot run safescale: %v\n", err)
		return false
	}

	// Check if tenant set corresponds to the content of the corresponding environment variable
	listStr, err := GetOutput("safescale tenant list")
	if err != nil {
		fmt.Printf("Cannot run safescale tenant list: %v\n", err)
		return false
	}
	if len(listStr) <= 0 {
		fmt.Println("No tenant found.")
		return false
	}

	providerOfCurrentTenant, err := GetOutput("safescale tenant get | jq -r .result.provider")
	if err != nil {
		fmt.Println(err)
		return false
	}
	if len(providerOfCurrentTenant) <= 0 {
		fmt.Println("No tenant set")
		return false
	}

	fmt.Printf("Looking for %s\n", providerOfCurrentTenant)

	providers.CurrentProvider, err = providers.FromString(strings.Trim(providerOfCurrentTenant, "\n"))
	if err != nil {
		fmt.Println(err)
		return false
	}

	key := providers.CurrentProvider.Key()
	if key == "" {
		fmt.Printf("Environment variable '%s' not found\n", key)
		return false
	}

	err = RunOnlyInIntegrationTest(key)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

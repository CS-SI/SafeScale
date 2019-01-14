/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	broker "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/utils"
)

const (
	curlGet  = "curl -kSsl -X GET --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\""
	curlPost = "curl -kSsl -X POST --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\" -d @- <<'EOF'\n%s\nEOF\n"
)

var kongProxyCheckedCache = utils.NewMapCache()

// KongController allows to control Kong, installed on a host
type KongController struct {
	host   *pb.Host
	broker broker.Client
}

// NewKongController ...
func NewKongController(host *pb.Host) (*KongController, error) {
	if host == nil {
		panic("host is nil!")
	}

	// Check if reverseproxy feature is installed on host
	rp, err := NewFeature("reverseproxy")
	if err != nil {
		return nil, fmt.Errorf("failed to find a feature called 'reverseproxy'")
	}
	present := false
	if anon, ok := kongProxyCheckedCache.Get(host.Name); ok {
		present = anon.(bool)
	} else {
		setErr := kongProxyCheckedCache.SetBy(host.Name, func() (interface{}, error) {
			target := NewHostTarget(host)
			results, err := rp.Check(target, Variables{}, Settings{})
			if err != nil {
				return nil, fmt.Errorf("failed to check if feature 'reverseproxy' is installed on gateway: %s", err.Error())
			}
			return results.Successful(), nil
		})
		if setErr != nil {
			return nil, setErr
		}
		present = true
	}
	if !present {
		return nil, fmt.Errorf("'reverseproxy' feature isn't installed on gateway")
	}

	return &KongController{
		host:   host,
		broker: broker.New(),
	}, nil
}

// Apply applies the rule to Kong proxy
// Currently, support rule types service, route and upstream
func (k *KongController) Apply(rule map[interface{}]interface{}, values *Variables) error {
	ruleName := rule["name"].(string)
	ruleType := rule["type"].(string)

	content, err := k.realizeRuleData(strings.Trim(rule["content"].(string), "\n"), *values)
	if err != nil {
		return err
	}

	// Analyzes the rule...
	var url string
	switch ruleType {
	case "service":
		url = "services/"

	case "route":
		url = "routes/"
		unjsoned := map[string]interface{}{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
		}
		unjsoned["protocols"] = []string{"https"}
		jsoned, _ := json.Marshal(&unjsoned)
		content = string(jsoned)

	case "upstream":
		url = "upstreams/"
		// Create upstream if it doesn't exist
		unjsoned := map[string]interface{}{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
		}
		upstreamName := unjsoned["name"].(string)
		url += upstreamName
		response, err := k.get(ruleName, url)
		if response == nil && err != nil {
			return err
		}
		if msg, ok := response["message"]; ok {
			if strings.ToLower(msg.(string)) == "not found" {
				err := k.createUpstream(upstreamName, values)
				if err != nil {
					return err
				}
			}
		}

		// Now ready to add target to upstream
		delete(unjsoned, "name")
		jsoned, _ := json.Marshal(&unjsoned)
		content = string(jsoned)
		url += "/targets"

	default:
		return fmt.Errorf("syntax error in rule '%s': %s isn't a valid type", ruleName, ruleType)
	}

	_, err = k.post(ruleName, url, content, values)
	if err != nil {
		log.Debugf("")
		return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
	}
	return nil
}

func (k *KongController) realizeRuleData(content string, v Variables) (string, error) {
	contentTmpl, err := template.New("proxy_rule").Parse(content)
	if err != nil {
		return "", fmt.Errorf("error preparing rule: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = contentTmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", err
	}
	return dataBuffer.String(), nil
}

func (k *KongController) createUpstream(name string, v *Variables) error {
	upstreamData := map[string]string{"name": name}
	jsoned, _ := json.Marshal(&upstreamData)
	response, err := k.post(name, "upstreams/", string(jsoned), v)
	if response == nil && err != nil {
		return err
	}
	if msg, ok := response["message"]; ok {
		return fmt.Errorf("failed to create upstream: %s", msg)
	}
	return nil
}

func (k *KongController) get(name, url string) (map[string]interface{}, error) {
	// Now apply the rule to Kong
	cmd := fmt.Sprintf(curlGet, url)
	retcode, stdout, _, err := broker.New().Ssh.Run(k.host.Name, cmd, broker.DefaultConnectionTimeout, broker.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return nil, fmt.Errorf("get '%s' failed: retcode=%d", name, retcode)
	}
	output := strings.Split(stdout, "\n")
	var response map[string]interface{}
	err = json.Unmarshal([]byte(output[0]), &response)
	if err != nil {
		return nil, err
	}
	if output[1] == "200" || output[1] == "201" {
		return response, nil
	}
	if msg, ok := response["message"]; ok {
		return response, fmt.Errorf("get failed: HTTP error code=%s: %s", output[1], msg.(string))
	}
	return response, fmt.Errorf("get failed with HTTP error code '%s'", output[1])
}

func (k *KongController) post(name, url, data string, v *Variables) (map[string]interface{}, error) {
	log.Debugf("deploy.install.kongctl.KongController::post() called")
	defer log.Debugf("deploy.install.kongctl.KongController::post() ended")

	// Now apply the rule to Kong
	cmd := fmt.Sprintf(curlPost, url, data)
	retcode, stdout, stderr, err := broker.New().Ssh.Run(k.host.Name, cmd, broker.DefaultConnectionTimeout, broker.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		log.Debugf("submit of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, fmt.Errorf("submit of rule '%s' failed: retcode=%d", name, retcode)
	}
	output := strings.Split(stdout, "\n")
	var response map[string]interface{}
	err = json.Unmarshal([]byte(output[0]), &response)
	if err != nil {
		return nil, err
	}
	if output[1] == "200" || output[1] == "201" {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
		return response, nil
	}
	if msg, ok := response["message"]; ok {
		return response, fmt.Errorf("post failed: HTTP Error code %s: %s", output[1], msg.(string))
	}
	return response, fmt.Errorf("post failed: HTTP error code '%s'", output[1])
}

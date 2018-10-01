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

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
)

const (
	curlGet  = "curl -Ssl -k -X GET --url https://localhost:8444/%s -H \"Content-Type:application/json\""
	curlPost = "curl -Ssl -k -X POST --url https://localhost:8444/%s -H \"Content-Type:application/json\" -d @- <<'EOF'\n%s\nEOF\n"
)

var kongProxyCheckedCache = NewMapCache()

// KongController allows to control Kong, installed on a host
type KongController struct {
	host   *pb.Host
	broker brokerclient.Client
}

// NewKongController ...
func NewKongController(host *pb.Host) (*KongController, error) {
	if host == nil {
		panic("host is nil!")
	}

	// Check if reverseproxy component is installed on gateway
	rp, err := NewComponent("reverseproxy")
	if err != nil {
		return nil, fmt.Errorf("no 'reverseproxy' component found")
	}
	present := false
	if anon, ok := kongProxyCheckedCache.Get(host.Name); ok {
		present = anon.(bool)
	} else {
		setErr := kongProxyCheckedCache.SetBy(host.Name, func() (interface{}, error) {
			target := NewHostTarget(host)
			results, err := rp.Check(target, Variables{})
			if err != nil {
				return nil, fmt.Errorf("failed to check if component 'reverseproxy' is installed on gateway: %s", err.Error())
			}
			return results.Successful(), nil
		})
		if setErr != nil {
			return nil, setErr
		}
	}
	if !present {
		return nil, fmt.Errorf("'reverseproxy' component isn't installed on gateway")
	}

	return &KongController{
		host:   host,
		broker: brokerclient.New(),
	}, nil
}

// Apply applies the rule to Kong proxy
// Currently, support rule types service, route and upstream
func (k *KongController) Apply(rule map[interface{}]interface{}, values Variables) error {
	ruleName := rule["name"].(string)
	ruleType := rule["type"].(string)

	// Analyzes the rule...
	content := strings.Trim(rule["content"].(string), "\n")
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
		cmd := fmt.Sprintf(curlGet, url+upstreamName)
		retcode, _, _, err := k.broker.Ssh.Run(k.host.Name, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
		if retcode != 0 {
			err := k.createUpstream(upstreamName, values)
			if err != nil {
				return err
			}
		}

		// Now ready to add target to upstream
		delete(unjsoned, "name")
		jsoned, _ := json.Marshal(&unjsoned)
		content = string(jsoned)

	default:
		return fmt.Errorf("syntax error in rule '%s': %s isn't a valid type", ruleName, ruleType)
	}

	err := k.execute(ruleName, url, content, values)
	if err != nil {
		return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
	}
	return nil
}

func (k *KongController) createUpstream(name string, v Variables) error {
	upstreamData := map[string]string{"name": name}
	jsoned, _ := json.Marshal(&upstreamData)
	return k.execute(name, "upstreams/", string(jsoned), v)
}

func (k *KongController) execute(name, url, data string, values Variables) error {
	// Now apply the rule to Kong
	tmpl, err := template.New("rule " + name).Parse(data)
	if err != nil {
		return err
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, values)
	if err != nil {
		return err
	}
	finalRule := dataBuffer.String()

	cmd := fmt.Sprintf(curlPost, url, finalRule)
	retcode, stdout, _, err := brokerclient.New().Ssh.Run(k.host.Name, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("execution of rule '%s' failed", name)
	}
	var response map[string]interface{}
	err = json.Unmarshal([]byte(stdout), &response)
	if err != nil {
		return err
	}
	if msg, ok := response["message"]; ok {
		return fmt.Errorf(msg.(string))
	}
	if id, ok := response["id"]; ok {
		values[name] = id.(string)
	}

	return nil
}

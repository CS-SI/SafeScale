package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/deploy/install/api"

	"github.com/CS-SI/SafeScale/system"
)

const (
	curlPost = "curl -Ssl -k -X POST --url https://localhost:8444/%s -H \"Content-Type:application/json\" -d @- <<'EOF'\n%s\nEOF\n"
)

var (
	componentScriptTemplate *template.Template
)

// validateClusterTargets validates targets on the cluster from the component specification
// Without error, returns 'master target', 'private node target' and 'public node target'
func validateClusterTargets(specs *viper.Viper) (string, string, string, error) {
	if !specs.IsSet("component.target.cluster") {
		return "", "", "", fmt.Errorf("component doesn't target a cluster")
	}

	master := strings.ToLower(strings.TrimSpace(specs.GetString("component.target.cluster.master")))
	switch master {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		master = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		master = "1"
	case "all":
		fallthrough
	case "*":
		master = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.target.cluster.master'", master)
	}

	privnode := strings.ToLower(strings.TrimSpace(specs.GetString("component.target.cluster.node.private")))
	switch privnode {
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		privnode = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		privnode = "1"
	case "":
		fallthrough
	case "all":
		fallthrough
	case "*":
		privnode = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.target.cluster.node.private'", privnode)
	}

	pubnode := strings.ToLower(strings.TrimSpace(specs.GetString("component.target.cluster.node.public")))
	switch pubnode {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		pubnode = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		pubnode = "1"
	case "all":
		fallthrough
	case "*":
		pubnode = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.target.cluster.node.public'", pubnode)
	}

	if master == "0" && privnode == "0" && pubnode == "0" {
		return "", "", "", fmt.Errorf("invalid 'component.target.cluster': no target designated")
	}
	return master, privnode, pubnode, nil
}

// UploadStringToRemoteFile creates a file 'filename' on remote 'host' with the content 'content'
func UploadStringToRemoteFile(content string, host *pb.Host, filename string) error {
	if content == "" {
		panic("content is empty!")
	}
	if host == nil {
		panic("host is nil!")
	}
	if filename == "" {
		panic("filename is empty!")
	}
	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %s", err.Error())
	}
	to := fmt.Sprintf("%s:%s", host.GetName(), filename)
	err = brokerclient.New().Ssh.Copy(f.Name(), to, brokerclient.DefaultTimeout)
	os.Remove(f.Name())
	if err != nil {
		return fmt.Errorf("failed to copy file to host: %s", err.Error())
	}
	return nil
}

// normalizeScript envelops the script with log redirection to /var/tmp/component.<name>.<action>.log
// and ensures BashLibrary are there
func normalizeScript(params map[string]interface{}) (string, error) {
	var err error

	if componentScriptTemplate == nil {
		// parse then execute the template
		componentScriptTemplate, err = template.New("normalize_script").Parse(componentScriptTemplateContent)
		if err != nil {
			return "", fmt.Errorf("error parsing bash template: %s", err.Error())
		}
	}

	// Configures BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return "", err
	}
	params["reserved_BashLibrary"] = bashLibrary

	dataBuffer := bytes.NewBufferString("")
	err = componentScriptTemplate.Execute(dataBuffer, params)
	if err != nil {
		return "", err
	}
	return dataBuffer.String(), nil
}

func replaceVariablesInString(text string, v api.Variables) (string, error) {
	tmpl, err := template.New("text").Parse(text)
	if err != nil {
		return "", fmt.Errorf("failed to parse: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", fmt.Errorf("failed to replace variables: %s", err.Error())
	}
	return dataBuffer.String(), nil
}

func findConcernedHosts(list []string, c api.Component) (string, error) {
	// No metadata yet for components, first host is designated concerned host
	if len(list) > 0 {
		return list[0], nil
	}
	return "", fmt.Errorf("no hosts")
	//for _, h := range list {
	//}
}

// installRequirements walks through requirements and installs them if needed
func installRequirements(c api.Component, t api.Target, v map[string]interface{}) error {
	specs := c.Specs()
	if specs.IsSet("component.requirements") {
		hostInstance, clusterInstance, nodeInstance := determineContext(t)
		msgHead := fmt.Sprintf("Checking requirements of component '%s'", c.DisplayName())
		var msgTail string
		if hostInstance != nil {
			msgTail = fmt.Sprintf("on host '%s'", hostInstance.host.Name)
		}
		if nodeInstance != nil {
			msgTail = fmt.Sprintf("on cluster node '%s'", nodeInstance.host.Name)
		}
		if clusterInstance != nil {
			msgTail = fmt.Sprintf("on cluster '%s'", clusterInstance.cluster.GetName())
		}
		log.Printf("%s %s...\n", msgHead, msgTail)
		for _, requirement := range specs.GetStringSlice("component.requirements") {
			needed, err := NewComponent(requirement)
			if err != nil {
				return fmt.Errorf("failed to find required component '%s': %s", requirement, err.Error())
			}
			log.Printf("Checking required component '%s' %s...\n", needed.DisplayName(), msgTail)
			ok, addResults, err := needed.Add(t, v)
			if err != nil {
				return fmt.Errorf("failed to install required component '%s': %s", requirement, err.Error())
			}
			if !ok {
				var errors []string
				for _, i := range addResults.Masters {
					if i != nil {
						errors = append(errors, i.Error())
					}
				}
				for _, i := range addResults.PrivateNodes {
					if i != nil {
						errors = append(errors, i.Error())
					}
				}
				for _, i := range addResults.PublicNodes {
					if i != nil {
						errors = append(errors, i.Error())
					}
				}
				msg := strings.Join(errors, "\n")
				return fmt.Errorf("failed to install required component '%s':\n%s", requirement, msg)
			}
		}
	}
	return nil
}

// proxyComponent applies the proxy rules defined in specification file (if there are some)
func proxyComponent(c api.Component, host *pb.Host) error {
	// First check if proxy is there
	broker := brokerclient.New()
	gw, err := broker.Host.Inspect(host.GetGatewayID(), brokerclient.DefaultTimeout)
	if err != nil {
		return fmt.Errorf("failed to apply proxy settings: %s", err.Error())
	}
	rp, err := NewComponent("reverseproxy")
	if err != nil {
		return fmt.Errorf("failed to apply proxy rules: %s", err)
	}
	target := NewHostTarget(gw)
	ok, _, err := rp.Check(target, api.Variables{})
	if err != nil {
		return fmt.Errorf("failed to apply proxy rules: %s", err.Error())
	}
	if !ok {
		return fmt.Errorf("failed to apply proxy rules, proxy isn't installed on gateway")
	}

	// Proxy is there, now get rules
	specs := c.Specs()
	anon := specs.Get("component.proxy.rules")
	rules, ok := anon.([]interface{})
	if !ok || len(rules) <= 0 {
		return nil
	}

	// Defines values of template parameters
	values := map[string]interface{}{
		"Hostname":  host.Name,
		"HostIP":    host.PRIVATE_IP,
		"GatewayIP": gw.PUBLIC_IP,
	}

	// Now submits all the rules to reverse proxy
	for _, r := range rules {
		rule := r.(map[interface{}]interface{})
		ruleName := rule["name"].(string)
		ruleType := rule["type"].(string)

		var url string
		switch ruleType {
		case "service":
			url = "services/"
		case "route":
			url = "routes/"
		default:
			return fmt.Errorf("syntax error in rule '%s': %s isn't a valid type", ruleName, ruleType)
		}
		content := strings.Trim(rule["content"].(string), "\n")
		if ruleType == "route" {
			unjsoned := map[string]interface{}{}
			err := json.Unmarshal([]byte(content), &unjsoned)
			if err != nil {
				return fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
			}
			unjsoned["protocols"] = []string{"https"}
			jsoned, _ := json.Marshal(&unjsoned)
			content = string(jsoned)
		}
		tmpl, err := template.New("rule " + ruleName).Parse(content)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmpl.Execute(dataBuffer, values)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		finalRule := dataBuffer.String()

		cmd := fmt.Sprintf(curlPost, url, finalRule)
		retcode, stdout, _, err := broker.Ssh.Run(gw.ID, cmd, brokerclient.DefaultTimeout)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		if retcode != 0 {
			return fmt.Errorf("failed to apply proxy rule '%s'", ruleName)
		}
		var response map[string]interface{}
		err = json.Unmarshal([]byte(stdout), &response)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rule '%s', invalid response: %s", ruleName, err.Error())
		}
		if msg, ok := response["message"]; ok {
			return fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, msg)
		}
		if id, ok := response["id"]; ok {
			values[ruleName] = id.(string)
		}
	}
	return nil
}

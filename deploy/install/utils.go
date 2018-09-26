package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"

	"github.com/CS-SI/SafeScale/utils/retry"

	"github.com/CS-SI/SafeScale/system"
)

const (
	curlPost           = "curl -Ssl -k -X POST --url https://localhost:8444/%s -H \"Content-Type:application/json\" -d @- <<'EOF'\n%s\nEOF\n"
	targetMasters      = "masters"
	targetPublicNodes  = "public_nodes"
	targetPrivateNodes = "private_nodes"
)

var (
	componentScriptTemplate *template.Template
)

// installerMap keeps a map of available installers sorted by Method
type installerMap map[Method.Enum]Installer

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
func UploadStringToRemoteFile(content string, host *pb.Host, filename string, owner, group, rights string) error {
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
	to := fmt.Sprintf("%s:%s", host.Name, filename)
	broker := brokerclient.New().Ssh
	retryErr := retry.WhileUnsuccessful(
		func() error {
			var retcode int
			retcode, _, _, err = broker.Copy(f.Name(), to, 15*time.Second, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 {
					// File may exist on target, try to remote it
					_, _, _, err = broker.Run(host.Name, fmt.Sprintf("sudo rm -f %s", filename), 15*time.Second, brokerclient.DefaultExecutionTimeout)
					return fmt.Errorf("file may exist on remote with inappropriate access rights, deleted it and retrying")
				}
				if system.IsSCPRetryable(retcode) {
					err = fmt.Errorf("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
				return nil
			}
			return nil
		},
		1*time.Second,
		2*time.Minute,
	)
	os.Remove(f.Name())
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to copy temporary file to '%s': %s", to, retryErr.Error())
		}
		return err
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + " " + filename
	}
	if group != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chgrp " + group + " " + filename
	}
	if rights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chmod " + rights + " " + filename
	}
	retryErr = retry.WhileUnsuccessful(
		func() error {
			var retcode int
			retcode, _, _, err = broker.Run(host.Name, cmd, 15*time.Second, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			if retcode != 0 {
				err = fmt.Errorf("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				return nil
			}
			return nil
		},
		2*time.Second,
		1*time.Minute,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to change rights of file '%s' on host '%s': %s", filename, host.Name, err.Error())
		default:
			return fmt.Errorf("failed to change rights of file '%s' on host '%s': %s", filename, host.Name, retryErr.Error())
		}
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

func replaceVariablesInString(text string, v Variables) (string, error) {
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

func findConcernedHosts(list []string, c *Component) (string, error) {
	// No metadata yet for components, first host is designated concerned host
	if len(list) > 0 {
		return list[0], nil
	}
	return "", fmt.Errorf("no hosts")
	//for _, h := range list {
	//}
}

// installRequirements walks through requirements and installs them if needed
func installRequirements(c *Component, t Target, v Variables) error {
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
			ok, addResults, err := needed.Add(t, v)
			if err != nil {
				return fmt.Errorf("failed to install required component '%s': %s", requirement, err.Error())
			}
			if !ok {
				return fmt.Errorf("failed to install required component '%s':\n%s", requirement, addResults.Errors())
			}
		}
	}
	return nil
}

// determineContext ...
func determineContext(t Target) (hT *HostTarget, cT *ClusterTarget, nT *NodeTarget) {
	hT = nil
	cT = nil
	nT = nil

	var ok bool

	hT, ok = t.(*HostTarget)
	if !ok {
		cT, ok = t.(*ClusterTarget)
		if !ok {
			nT, ok = t.(*NodeTarget)
		}
	}
	return
}

var proxyInstalledCache = NewMapCache()

// proxyComponent applies the proxy rules defined in specification file (if there are some)
func proxyComponent(c *Component, host *pb.Host) error {
	// First check if proxy is there
	broker := brokerclient.New()
	gw := gatewayFromHost(host)
	if gw == nil {
		return fmt.Errorf("failed to apply proxy settings, gateway of host not found")
	}
	rp, err := NewComponent("reverseproxy")
	if err != nil {
		return fmt.Errorf("failed to apply proxy rules: %s", err)
	}
	var (
		present bool
	)
	if anon, ok := proxyInstalledCache.Get(gw.Name); ok {
		present = anon.(bool)
	} else {
		setErr := proxyInstalledCache.SetBy(gw.Name, func() (interface{}, error) {
			target := NewHostTarget(gw)
			present, _, err = rp.Check(target, Variables{})
			if err != nil {
				return nil, fmt.Errorf("failed to apply proxy rules: %s", err.Error())
			}
			return present, nil
		})
		if setErr != nil {
			return setErr
		}
	}
	if !present {
		return fmt.Errorf("failed to apply proxy rules, proxy isn't installed on gateway '%s'", gw.Name)
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
		retcode, stdout, _, err := broker.Ssh.Run(gw.Name, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
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

// Check if required parameters defined in specification file have been set in 'v'
func checkParameters(c *Component, v Variables) error {
	specs := c.Specs()
	if specs.IsSet("component.parameters") {
		params := specs.GetStringSlice("component.parameters")
		for _, k := range params {
			if _, ok := v[k]; !ok {
				return fmt.Errorf("missing value for parameter '%s'", k)
			}
		}
	}
	return nil
}

// setImplicitParameters configures parameters that are implicitely defined, based on context
func setImplicitParameters(t Target, v Variables) {
	hT, cT, nT := determineContext(t)
	if cT != nil {
		cluster := cT.cluster
		config := cluster.GetConfig()
		v["ClusterName"] = cluster.GetName()
		v["GatewayIP"] = config.GatewayIP
		if _, ok := v["Username"]; !ok {
			v["Username"] = "cladm"
			v["Password"] = config.AdminPassword
		}
		return
	}

	var host *pb.Host
	if nT != nil {
		host = nT.HostTarget.host
	}
	if hT != nil {
		host = hT.host
	}
	v["Hostname"] = host.Name
	v["HostIP"] = host.PRIVATE_IP
	gw := gatewayFromHost(host)
	if gw != nil {
		v["GatewayIP"] = gw.PRIVATE_IP
	}
	if _, ok := v["Username"]; !ok {
		v["Username"] = "gpac"
	}
}

func gatewayFromHost(host *pb.Host) *pb.Host {
	broker := brokerclient.New()
	gw, err := broker.Host.Inspect(host.GetGatewayID(), brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return nil
	}
	return gw
}

func validateClusterSizing(c *Component, cluster clusterapi.Cluster) error {
	specs := c.Specs()
	yamlKey := "component.requirements.clusterSizing." + strings.ToLower(cluster.GetConfig().Flavor.String())
	if !specs.IsSet(yamlKey) {
		return nil
	}
	sizing := specs.GetStringMap(yamlKey)
	if anon, ok := sizing["minMasters"]; ok {
		minMasters := anon.(int)
		curMasters := len(cluster.ListMasterIDs())
		if curMasters < minMasters {
			return fmt.Errorf("cluster doesn't meet the minimum number of masters (%d < %d)", curMasters, minMasters)
		}
	}
	if anon, ok := sizing["minPrivateNodes"]; ok {
		minNodes := anon.(int)
		curNodes := len(cluster.ListNodeIDs(false))
		if curNodes < minNodes {
			return fmt.Errorf("cluster doesn't meet the minimum number of private nodes (%d < %d)", curNodes, minNodes)
		}
	}
	if anon, ok := sizing["minPublicNodes"]; ok {
		minNodes := anon.(int)
		curNodes := len(cluster.ListNodeIDs(true))
		if curNodes < minNodes {
			return fmt.Errorf("cluster doesn't meet the minimum number of public nodes (%d < %d)", curNodes, minNodes)
		}
	}
	return nil
}

package install

import (
	"bytes"
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

var (
	componentScriptTemplate *template.Template
)

// validateClusterTargets validates targets on the cluster from the component specification
// Without error, returns 'master target', 'private node target' and 'public node target'
func validateClusterTargets(specs *viper.Viper) (string, string, string, error) {
	if !specs.IsSet("component.targeting.cluster") {
		return "", "", "", fmt.Errorf("component doesn't target a cluster")
	}

	master := strings.ToLower(strings.TrimSpace(specs.GetString("component.targeting.cluster.master")))
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
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.targeting.cluster.master'", master)
	}

	privnode := strings.ToLower(strings.TrimSpace(specs.GetString("component.targeting.cluster.node.private")))
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
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.targeting.cluster.node.private'", privnode)
	}

	pubnode := strings.ToLower(strings.TrimSpace(specs.GetString("component.targeting.cluster.node.public")))
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
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'component.targeting.cluster.node.public'", pubnode)
	}

	if master == "0" && privnode == "0" && pubnode == "0" {
		return "", "", "", fmt.Errorf("invalid 'component.targeting.cluster': no target designated")
	}
	return master, privnode, pubnode, nil
}

// uploadStringToTargetFile creates a file 'filename' on target 'host' with the content 'content'
func uploadStringToTargetFile(content string, host *pb.Host, filename string) error {
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
		return err
	}
	to := fmt.Sprintf("%s:%s", host.GetName(), filename)
	err = brokerclient.New().Ssh.Copy(f.Name(), to, brokerclient.DefaultTimeout)
	os.Remove(f.Name())
	return err
}

// realizeScript envelops the script with log redirection to /var/tmp/component.<name>.<action>.log
// and ensures CommonTools are there
func realizeScript(params map[string]interface{}) (string, error) {
	var err error

	if componentScriptTemplate == nil {
		// parse then execute the template
		componentScriptTemplate, err = template.New("component_script.sh").Parse(componentScriptTemplateContent)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
	}

	// Configures CommonTools template var
	commonTools, err := system.RealizeCommonTools()
	if err != nil {
		return "", err
	}
	params["reserved_CommonTools"] = commonTools

	dataBuffer := bytes.NewBufferString("")
	err = componentScriptTemplate.Execute(dataBuffer, params)
	if err != nil {
		return "", fmt.Errorf("failed to realize %s script: %s", params["Action"], err.Error())
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
func installRequirements(specs *viper.Viper, t api.Target, v map[string]interface{}) error {
	if specs.IsSet("component.requirements") {
		for _, requirement := range specs.GetStringSlice("component.requirements") {
			needed, err := NewComponent(requirement)
			if err != nil {
				return fmt.Errorf("failed to find a required component '%s': %s", requirement, err.Error())
			}
			ok, _, err := needed.Check(t)
			if err != nil {
				return fmt.Errorf("failed to check state of required component '%s': %s", requirement, err.Error())
			}
			if !ok {
				log.Printf("Installing requirement '%s'...", requirement)
				ok, addResults, err := needed.Add(t, v)
				if err != nil {
					return fmt.Errorf("failed to run installation of required component '%s': %s", requirement, err.Error())
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
	}
	return nil
}

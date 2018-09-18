package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
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

type stepTargets map[string]string

func (st stepTargets) parse() (string, string, string, error) {
	var masterT, privnodeT, pubnodeT string

	switch strings.ToLower(st[targetMasters]) {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		masterT = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		masterT = "1"
	case "all":
		fallthrough
	case "*":
		masterT = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", masterT, targetMasters)
	}

	switch strings.ToLower(st[targetPrivateNodes]) {
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		privnodeT = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		privnodeT = "1"
	case "":
		fallthrough
	case "all":
		fallthrough
	case "*":
		privnodeT = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", privnodeT, targetPrivateNodes)
	}

	switch strings.ToLower(st[targetPublicNodes]) {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		pubnodeT = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		pubnodeT = "1"
	case "all":
		fallthrough
	case "*":
		pubnodeT = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", pubnodeT, targetPublicNodes)
	}

	if masterT == "0" && privnodeT == "0" && pubnodeT == "0" {
		return "", "", "", fmt.Errorf("no targets identified")
	}
	return masterT, privnodeT, pubnodeT, nil
}

type worker struct {
	component *Component
	target    Target
	method    Method.Enum
	action    Action.Enum
	pace      string

	host    *pb.Host
	node    bool
	cluster clusterapi.Cluster

	availableMaster      *pb.Host
	availablePrivateNode *pb.Host
	availablePublicNode  *pb.Host

	allMasters      []*pb.Host
	allPrivateNodes []*pb.Host
	allPublicNodes  []*pb.Host

	rootKey string
}

// NewWorker ...
func NewWorker(c *Component, t Target, m Method.Enum, a Action.Enum) (*worker, error) {
	w := worker{
		component: c,
		target:    t,
		method:    m,
		action:    a,
	}
	hT, cT, nT := determineContext(t)
	if cT != nil {
		w.cluster = cT.cluster
	}
	if hT != nil {
		w.host = hT.host
	}
	if nT != nil {
		w.host = nT.host
		w.node = true
	}

	w.rootKey = "component.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
	specs := w.component.Specs()
	if !specs.IsSet(w.rootKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), w.rootKey)
	}
	paceKey := w.rootKey + ".pace"
	if !specs.IsSet(paceKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), paceKey)
	}
	w.pace = specs.GetString(paceKey)

	return &w, nil
}

// CanProceed tells if the combination Component/Target can work
func (w *worker) CanProceed() bool {
	if w.cluster != nil {
		return validateContextForCluster(w.component, w.cluster)
	}
	// TODO: check if host satisfy requirements
	return validateContextForHost(w.component, w.host)
}

// validateContextForHost ...
func validateContextForHost(c *Component, host *pb.Host) bool {
	specs := c.Specs()
	if specs.IsSet("component.context.host") {
		value := strings.ToLower(specs.GetString("component.context.host"))
		return value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	return false
}

// AvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) AvailableMaster() (*pb.Host, error) {
	if w.cluster == nil {
		return nil, fmt.Errorf("can't get masters, target not a cluster")
	}
	if w.availableMaster == nil {
		hostID, err := w.cluster.FindAvailableMaster()
		if err != nil {
			return nil, err
		}
		w.availableMaster, err = brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return nil, err
		}
	}
	return w.availableMaster, nil
}

// AvailableNode finds a node available and will use this one during all the install session
func (w *worker) AvailableNode(public bool) (*pb.Host, error) {
	if w.cluster == nil {
		return nil, fmt.Errorf("can't get a node, target not a cluster")
	}
	found := false
	if public {
		found = w.availablePublicNode != nil
	} else {
		found = w.availablePrivateNode != nil
	}
	if !found {
		hostID, err := w.cluster.FindAvailableNode(public)
		if err != nil {
			return nil, err
		}
		host, err := brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return nil, err
		}
		if public {
			w.availablePublicNode = host
		} else {
			w.availablePrivateNode = host
		}
	}
	if public {
		return w.availablePublicNode, nil
	}
	return w.availablePrivateNode, nil
}

// AllMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) AllMasters() ([]*pb.Host, error) {
	if w.cluster == nil {
		return nil, fmt.Errorf("can't get list of masters, target not a cluster")
	}
	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []*pb.Host{}
		broker := brokerclient.New().Host
		for _, i := range w.cluster.ListMasterIDs() {
			host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return nil, err
			}
			w.allMasters = append(w.allMasters, host)
		}
	}
	return w.allMasters, nil
}

// AllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the install session
func (w *worker) AllNodes(public bool) ([]*pb.Host, error) {
	if w.cluster == nil {
		return nil, fmt.Errorf("can't get list of masters, target not a cluster")
	}
	found := false
	if public {
		found = w.allPublicNodes != nil && len(w.allPublicNodes) > 0
	} else {
		found = w.allPrivateNodes != nil && len(w.allPrivateNodes) > 0
	}
	if !found {
		brokerhost := brokerclient.New().Host
		allHosts := []*pb.Host{}
		nodes := w.cluster.ListNodeIDs(public)
		for _, i := range nodes {
			host, err := brokerhost.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return nil, err
			}
			allHosts = append(allHosts, host)
		}
		if public {
			w.allPublicNodes = allHosts
		} else {
			w.allPrivateNodes = allHosts
		}
	}
	if public {
		return w.allPublicNodes, nil
	}
	return w.allPrivateNodes, nil

}

// Proceed executes the action
func (w *worker) Proceed(v Variables) (map[string]stepErrors, error) {
	specs := w.component.Specs()

	results := map[string]stepErrors{}

	stepsKey := w.rootKey + ".steps"
	steps := specs.GetStringSlice(stepsKey)

	for _, k := range steps {
		log.Printf("executing step '%s'...\n", k)

		stepKey := stepsKey + "." + k
		var (
			runContent string
			stepT      stepTargets
			ok         bool
		)

		if !specs.IsSet(stepKey) {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		}
		stepMap := specs.GetStringMap(stepKey)
		if stepT, ok = stepMap["targets"].(stepTargets); !ok {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s.targets' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		}

		if runContent, ok = stepMap["run"].(string); !ok {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s.run' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		}

		// If there is an options file (for now specific to DCOS), upload it to the remote
		optionsFileContent := ""
		if specs.IsSet(stepKey + ".options") {
			var (
				avails  = map[string]interface{}{}
				ok      bool
				content interface{}
			)
			complexity := strings.ToLower(w.cluster.GetConfig().Complexity.String())
			options := specs.GetStringMap(stepKey + ".options")
			for k, anon := range options {
				avails[strings.ToLower(k)] = anon
			}
			if content, ok = avails[complexity]; !ok {
				if complexity == strings.ToLower(Complexity.Large.String()) {
					complexity = Complexity.Normal.String()
				}
				if complexity == strings.ToLower(Complexity.Normal.String()) {
					if content, ok = avails[complexity]; !ok {
						content, ok = avails[Complexity.Small.String()]
					}
				}
			}
			if ok {
				optionsFileContent = content.(string)
				v["options"] = "--options=/var/tmp/options.json"
			}
		} else {
			v["options"] = ""
		}

		wallTime := 0
		wallTimeKey := stepKey + ".wall_time"
		if specs.IsSet(wallTimeKey) {
			wallTime = specs.GetInt(wallTimeKey)
		}
		if wallTime == 0 {
			wallTime = 5
		}

		templateCommand, err := normalizeScript(Variables{
			"reserved_Name":    w.component.BaseFilename(),
			"reserved_Content": runContent,
			"reserved_Action":  strings.ToLower(w.action.String()),
		})
		if err != nil {
			return results, err
		}

		step := step{
			Worker:             w,
			Name:               k,
			Targets:            stepT,
			Script:             templateCommand,
			WallTime:           time.Duration(wallTime) * time.Minute,
			OptionsFileContent: optionsFileContent,
			YamlKey:            stepKey,
		}
		results[k], err = step.Run(v)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

type step struct {
	Worker             *worker
	Name               string
	Action             Action.Enum
	Targets            stepTargets
	Script             string
	WallTime           time.Duration
	YamlKey            string
	OptionsFileContent string
}

// Run executes the step on all the concerned hosts
func (is *step) Run(v Variables) (stepErrors, error) {
	// Determine list of hosts concerned by the step
	hostsList, err := is.identifyHosts(is.Worker, is.Targets)
	if err != nil {
		return nil, err
	}

	// Empty results
	results := stepErrors{}

	broker := brokerclient.New()
	for _, host := range hostsList {
		// Updates variables in step script
		command, err := replaceVariablesInString(is.Script, v)
		if err != nil {
			return results, fmt.Errorf("failed to finalize installer script: %s", err.Error())
		}

		// If options file is defined, upload it to the remote host
		if is.OptionsFileContent != "" {
			err := UploadStringToRemoteFile(is.OptionsFileContent, host, "/var/tmp/options.json", "cladm", "gpac", "ug+rw-x,o-rwx")
			if err != nil {
				return results, err
			}
		}

		// Uploads then executes command
		filename := fmt.Sprintf("/var/tmp/%s_add.sh", is.Worker.component.BaseFilename())
		err = UploadStringToRemoteFile(command, host, filename, "", "", "")
		if err != nil {
			return results, err
		}
		//if debug {
		if true {
			command = fmt.Sprintf("sudo bash %s", filename)
		} else {
			command = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s /var/tmp/options.json; exit $rc", filename, filename)
		}

		// Executes the script on the remote host
		retcode, _, _, err := broker.Ssh.Run(host.Name, command, brokerclient.DefaultConnectionTimeout, is.WallTime)
		if err != nil {
			return results, err
		}
		err = nil
		ok := retcode == 0
		if !ok {
			err = fmt.Errorf("installer step failed (retcode=%d)", retcode)
		}
		results[host.Name] = err
	}
	return results, nil
}

// IdentifyHosts identifies hosts concerned by the step
func (is *step) identifyHosts(w *worker, targets stepTargets) ([]*pb.Host, error) {
	//specs := is.Worker.component.Specs()

	masterT, privnodeT, pubnodeT, err := targets.parse()
	if err != nil {
		return nil, err
	}

	hostsList := []*pb.Host{}
	switch masterT {
	case "1":
		host, err := is.Worker.AvailableMaster()
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		all, err := is.Worker.AllMasters()
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, all...)
	}
	switch privnodeT {
	case "1":
		host, err := is.Worker.AvailableNode(false)
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		hosts, err := is.Worker.AllNodes(false)
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, hosts...)
	}
	switch pubnodeT {
	case "1":
		host, err := is.Worker.AvailableNode(true)
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		hosts, err := is.Worker.AllNodes(true)
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, hosts...)
	}

	return hostsList, nil
}

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

// validateContextForCluster checks if the flavor of the cluster is listed in component specification
// 'component.context.cluster'.
// If no flavors is listed, no flavors are authorized
func validateContextForCluster(c *Component, cluster clusterapi.Cluster) bool {
	specs := c.Specs()
	config := cluster.GetConfig()
	clusterFlavor := config.Flavor
	ok := true
	if specs.IsSet("component.target.cluster.flavors") {
		flavors := specs.GetStringSlice("component.target.cluster.flavors")
		for _, k := range flavors {
			f := strings.ToLower(k)
			if clusterFlavor == Flavor.FromString(f) {
				break
			}
		}
	}
	return ok
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

// Cache is an interface for caching elements
type Cache interface {
	SetBy(string, func() (interface{}, error)) error
	Set(string, interface{}) error
	ForceSetBy(string, func() (interface{}, error)) error
	ForceSet(string, interface{}) error
	Reset(string) Cache
	Get(string) (interface{}, bool)
	GetOrDefault(string, interface{}) interface{}
}

// MapCache implements Cache interface using map
type MapCache struct {
	lock  sync.RWMutex
	cache map[string]interface{}
}

// NewMapCache ...
func NewMapCache() Cache {
	return &MapCache{
		cache: map[string]interface{}{},
	}
}

// SetBy ...
func (c *MapCache) SetBy(key string, by func() (interface{}, error)) error {
	c.lock.Lock()
	if _, ok := c.cache[key]; !ok {
		value, err := by()
		if err != nil {
			return err
		}
		c.cache[key] = value
	}
	c.lock.Unlock()
	return nil
}

// ForceSetBy ...
func (c *MapCache) ForceSetBy(key string, by func() (interface{}, error)) error {
	c.lock.Lock()
	value, err := by()
	if err != nil {
		return err
	}
	c.cache[key] = value
	c.lock.Unlock()
	return nil
}

// Set ...
func (c *MapCache) Set(key string, value interface{}) error {
	return c.SetBy(key, func() (interface{}, error) { return value, nil })
}

// ForceSet ...
func (c *MapCache) ForceSet(key string, value interface{}) error {
	return c.ForceSetBy(key, func() (interface{}, error) { return value, nil })
}

// Reset ...
func (c *MapCache) Reset(key string) Cache {
	c.lock.Lock()
	delete(c.cache, key)
	c.lock.Unlock()
	return c
}

// Get ...
func (c *MapCache) Get(key string) (value interface{}, ok bool) {
	c.lock.RLock()
	value, ok = c.cache[key]
	c.lock.RUnlock()
	return
}

// GetOrDefault ...
func (c *MapCache) GetOrDefault(key string, def interface{}) (value interface{}) {
	var ok bool
	value, ok = c.Get(key)
	if !ok {
		value = def
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

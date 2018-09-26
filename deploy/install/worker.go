package install

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

const (
	yamlPaceKeyword     = "pace"
	yamlStepsKeyword    = "steps"
	yamlTargetsKeyword  = "targets"
	yamlRunKeyword      = "run"
	yamlOptionsKeyword  = "options"
	yamlWallTimeKeyword = "wallTime"
)

type worker struct {
	component *Component
	target    Target
	method    Method.Enum
	action    Action.Enum

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

	// 'pace' tells the order of execution
	pace := specs.GetString(w.rootKey + "." + yamlPaceKeyword)
	if pace == "" {
		return nil, fmt.Errorf("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
	}
	// 'steps' describes the steps of the action
	stepsKey := w.rootKey + "." + yamlStepsKeyword
	steps := specs.GetStringMap(stepsKey)
	if len(steps) <= 0 {
		return nil, fmt.Errorf("nothing to do")
	}
	order := strings.Split(pace, ",")
	for _, k := range order {
		log.Printf("executing step '%s'...\n", k)

		stepKey := stepsKey + "." + k
		var (
			runContent string
			stepT      = stepTargets{}
			options    = map[string]string{}
			ok         bool
			anon       interface{}
			err        error
		)
		stepMap, ok := steps[k].(map[string]interface{})
		if !ok {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		}
		// if !specs.IsSet(stepKey) {
		// 	msg := `syntax error in component '%s' specification file (%s):
		// 	no key '%s' found`
		// 	return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		// }
		// stepMap := specs.GetStringMap(stepKey)
		anon, ok = stepMap[yamlTargetsKeyword]
		if ok {
			for i, j := range anon.(map[string]interface{}) {
				stepT[i] = j.(string)
			}
		} else {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s.%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey, yamlTargetsKeyword)
		}

		anon, ok = stepMap[yamlRunKeyword]
		if ok {
			runContent = anon.(string)
		} else {
			msg := `syntax error in component '%s' specification file (%s):
			no key '%s.%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey, yamlRunKeyword)
		}

		// If there is an options file (for now specific to DCOS), upload it to the remote host
		optionsFileContent := ""
		anon, ok = stepMap[yamlOptionsKeyword]
		if ok {
			for i, j := range anon.(map[string]interface{}) {
				options[i] = j.(string)
			}
			var (
				avails  = map[string]interface{}{}
				ok      bool
				content interface{}
			)
			complexity := strings.ToLower(w.cluster.GetConfig().Complexity.String())
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
		anon, ok = stepMap[yamlWallTimeKeyword]
		if ok {
			wallTime, err = strconv.Atoi(anon.(string))
			if err != nil {
				log.Printf("Invalid value '%s' for '%s.%s', ignored.", anon.(string), w.rootKey, yamlWallTimeKeyword)
			}
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

// validateContextForHost ...
func validateContextForHost(c *Component, host *pb.Host) bool {
	specs := c.Specs()
	if specs.IsSet("component.context.host") {
		value := strings.ToLower(specs.GetString("component.context.host"))
		return value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	return false
}

/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package clusters

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// TargetType returns the type of the target
//
// satisfies install.Targetable interface
func (c *cluster) TargetType() string {
	return "cluster"
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies feature.Targetable interface
func (c *cluster) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if c == nil {
		logrus.Error(scerr.InvalidInstanceError().Error())
		return nil
	}
	if task == nil {
		logrus.Errorf(scerr.InvalidParameterError("task", "cannot be nil").Error())
		return nil
	}

	task.Lock(c.core.lock)
	defer task.Unlock(c.core.lock)

	if c.installMethods == nil {
		c.installMethods = map[uint8]installmethod.Enum{}
		var index uint8
		flavor, err := c.Flavor()
		if err == nil {
			switch flavor {
			case Flavor.K8S:
				index++
				mc.installMethods[index] = installmethod.Helm
			}
		}
		index++
		c.installMethods[index] = installmethod.Bash
	}
	return c.installMethods
}

// InstalledFeatures returns a list of installed features
func (c *cluster) InstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// ComplementFeatureParameters configures parameters that are implicitely defined, based on target
func (c *cluster) ComplementFeatureParameters(task concurrency.Task, v data.Map) error {
	var err error
	var complexity Complexity.Enum
	if complexity, err = c.Complexity(); err != nil {
		return err
	}
	v["ClusterComplexity"] = strings.ToLower(complexity.String())
	var flavor ClusterFlavor.Enum
	if flavor, err = c.Flavor(); err != nil {
		return err
	}
	v["ClusterFlavor"] = strings.ToLower(flavor.String())
	networkCfg, err := c.NetworkConfig(task)
	if err != nil {
		return err
	}
	// FIXME: network parameters probably incomplete
	v["GatewayIP"] = networkCfg.GatewayIP
	v["PublicIP"] = networkCfg.PublicIP
	v["ClusterMasterIDs"], err = c.ListMasterIDs(task)
	if err != nil {
		return err
	}
	v["ClusterMasterIPs"], err = c.ListMasterIPs(task)
	if err != nil {
		return err
	}
	if _, ok := v["ClusterAdminUsername"]; !ok {
		v["ClusterAdminUsername"] = "cladm"
	}
	if _, ok := v["ClusterAdminPassword"]; !ok {
		if v["ClusterAdminPassword"], err = c.AdminPassword(); err != nil {
			return err
		}
	}
	if _, ok := v["CIDR"]; !ok {
		v["CIDR"] = networkCfg.CIDR
	}
	return nil
}

// AddFeature installs a feature on the cluster
func (c *Cluster) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.InstallSettings) (resources.InstallResults, error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError().Error()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	feat, err := featurefactorys.New(task, name)
	if err != nil {
		return nil, err
	}
	return feat.Add(c, vars, settings)
}

// CheckFeature tells if a feature is installed on the cluster
func (c *Cluster) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.InstallSettings) (resources.InstallResults, error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError().Error()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	feat, err := featurefactory.New(task, name)
	if err != nil {
		return nil, err
	}

	return feat.Check(c, vars, settings)
}

// DeleteFeature uninstalls a feature from the cluster
func (c *cluster) DeleteFeature(task concurrency.Task, name string, vars data.Map, settings resources.InstallSettings) (resources.InstallResults, error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError().Error()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	feat, err := featurefactory.New(task, name)
	if err != nil {
		return nil, err
	}

	return feat.Delete(c, vars, settings)
}


// ExecuteScript executes the script template with the parameters on target Host
func (c *cluster) ExecuteScript(
	task concurrency.Task, box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string,
) (errCode int, stdOut string, stdErr string, err error) {
	tracer := concurrency.NewTracer(nil, "("+hostID+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if c == nil {
		return 0, "", "", scerr.InvalidInstanceError()
	}

	// Configures reserved_BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return 0, "", "", err
	}
	data["reserved_BashLibrary"] = bashLibrary

	script, path, err := realizeTemplate(box, funcMap, tmplName, data, tmplName)
	if err != nil {
		return 0, "", "", err
	}

	hidesOutput := strings.Contains(script, "set +x\n")
	if hidesOutput {
		script = strings.Replace(script, "set +x\n", "\n", 1)
		if strings.Contains(script, "exec 2>&1\n") {
			script = strings.Replace(script, "exec 2>&1\n", "exec 2>&7\n", 1)
		}
	}

	err = uploadScriptToFileInHost(script, hostID, path)
	if err != nil {
		return 0, "", "", err
	}

	cmd := fmt.Sprintf("sudo chmod u+rx %s;sudo bash %s;exit ${PIPESTATUS}", path, path)
	if hidesOutput {
		cmd = fmt.Sprintf("sudo chmod u+rx %s;sudo bash -c \"BASH_XTRACEFD=7 %s 7> /tmp/captured 2>&7\";echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured; sudo rm /tmp/captured;exit `cat /tmp/errc`", path, path)
	}

	return client.New().SSH.Run(task, hostID, cmd, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
}

// installNodeRequirements ...
func (c *cluster) installNodeRequirements(task concurrency.Task, nodeType clusternodetype.Enum, pbHost *protocol.Host, hostLabel string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if c.makers.GetTemplateBox == nil {
		return scerr.InvalidParameterError("c.makers.GetTemplateBox", "cannot be nil")
	}

	netCfg, err := c.NetworkConfig(task)
	if err != nil {
		return err
	}

	// Get installation script based on node type; if == "", do nothing
	script, params := c.getNodeInstallationScript(task, nodeType)
	if script == "" {
		return nil
	}

	box, err := c.makers.GetTemplateBox()
	if err != nil {
		return err
	}

	globalSystemRequirements := ""
	if c.makers.GetGlobalSystemRequirements != nil {
		result, err := c.makers.GetGlobalSystemRequirements(task, b)
		if err != nil {
			return err
		}
		globalSystemRequirements = result
	}
	params["reserved_CommonRequirements"] = globalSystemRequirements

	if nodeType == NodeType.Master {
		tp := c.service.GetTenantParameters()
		content := map[string]interface{}{
			"tenants": []map[string]interface{}{
				tp,
			},
		}
		jsoned, err := json.MarshalIndent(content, "", "    ")
		if err != nil {
			return err
		}
		params["reserved_TenantJSON"] = string(jsoned)

		// Finds the folder where the current binary resides
		var (
			exe       string
			binaryDir string
			path      string
		)
		exe, _ = os.Executable()
		if exe != "" {
			binaryDir = filepath.Dir(exe)
		}

		// Uploads safescale binary
		if binaryDir != "" {
			path = binaryDir + "/safescale"
		}
		if path == "" {
			path, err = exec.LookPath("safescale")
			if err != nil {
				msg := "failed to find local binary 'safescale', make sure its path is in environment variable PATH"
				return fmt.Errorf(utils.Capitalize(msg))
			}
		}
		err = features.UploadFile(path, pbHost, "/opt/safescale/bin/safescale", "root", "root", "0755")
		if err != nil {
			return fmt.Errorf("failed to upload 'safescale' binary': %s", err.Error())
		}

		// Uploads safescaled binary
		path = ""
		if binaryDir != "" {
			path = binaryDir + "/safescaled"
		}
		if path == "" {
			path, err = exec.LookPath("safescaled")
			if err != nil {
				msg := "failed to find local binary 'safescaled', make sure its path is in environment variable PATH"
				return fmt.Errorf(utils.Capitalize(msg))
			}
		}
		err = features.UploadFile(path, pbHost, "/opt/safescale/bin/safescaled", "root", "root", "0755")
		if err != nil {
			return fmt.Errorf("failed to upload 'safescaled' binary': %s", err.Error())
		}

		// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
		suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX")
		if suffix != "" {
			cmdTmpl := "sudo sed -i '/^SAFESCALE_METADATA_SUFFIX=/{h;s/=.*/=%s/};${x;/^$/{s//SAFESCALE_METADATA_SUFFIX=%s/;H};x}' /etc/environment"
			cmd := fmt.Sprintf(cmdTmpl, suffix, suffix)
			retcode, stdout, stderr, err := client.New().SSH.Run(task, pbHost.Id, cmd, client.DefaultConnectionTimeout, 2*temporal.GetLongOperationTimeout())
			if err != nil {
				msg := fmt.Sprintf("failed to submit content of SAFESCALE_METADATA_SUFFIX to host '%s': %s", pbHost.Name, err.Error())
				return fmt.Errorf(utils.Capitalize(msg))
			}
			if retcode != 0 {
				output := stdout
				if output != "" && stderr != "" {
					output += "\n" + stderr
				} else if stderr != "" {
					output = stderr
				}
				msg := fmt.Sprintf("failed to copy content of SAFESCALE_METADATA_SUFFIX to host '%s': %s", pbHost.Name, output)
				return fmt.Errorf(utils.Capitalize(msg))
			}
		}
	}

	var dnsServers []string
	cfg, err := c.service.GetConfigurationOptions()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity := c.Identity(task)
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	list, err := c.ListMasterIPs(task)
	if err != nil {
		return err
	}
	params["MasterIPs"] = list.Values()
	params["CladmPassword"] = identity.AdminPassword
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP

	retcode, stdout, stderr, err := b.ExecuteScript(ctx, box, funcMap, script, params, pbHost.Id)
	if err != nil {
		return err
	}

	if retcode != 0 {
		return handleExecuteScriptReturn(retcode, stdout, stderr, err, fmt.Sprintf("[%s] system requirements installation failed", hostLabel))
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

func handleExecuteScriptReturn(retcode int, stdout string, stderr string, err error, msg string) error {
	if retcode == 0 {
		return nil
	}

	var collected []string
	if stdout != "" {
		errLines := strings.Split(stdout, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}
	if stderr != "" {
		errLines := strings.Split(stderr, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}

	if len(collected) > 0 {
		if err != nil {
			return scerr.Wrap(err, fmt.Sprintf("%s: std error [%s]", msg, collected))
		}
		return fmt.Errorf("%s: std error [%s]", msg, strings.Join(collected, ";"))
	}

	return nil
}

// Installs reverseproxy
func (c *cluster) installReverseProxy(task concurrency.Task) (err error) {
	defer scerr.OnPanic(&err)()

	identity := c.Identity(task)
	clusterName := identity.Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
			featuresv1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["reverseproxy"]
			return nil
		})
	})
	if err != nil {
		return err
	}
	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'edgeproxy4network'", clusterName)
		feat, err := features.NewEmbeddedFeature(task, "edgeproxy4network")
		if err != nil {
			return err
		}
		results, err := feat.Add(c, features.Variables{}, features.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (c *cluster) installRemoteDesktop(task concurrency.Task) (err error) {
	defer scerr.OnPanic(&err)()

	identity := c.Identity(task)
	clusterName := identity.Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	err = b.cluster.GetProperties(task).Inspect(clusterproperty.FeaturesV1, func(v interface{}) error {
		featuresv1, ok := clonable.(*propertiesv1.ClusterFeatures)
		if !ok {
			return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		_, disabled = featuresV1.Disabled["remotedesktop"]
		return nil
	})
	if err != nil {
		return err
	}
	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'remotedesktop'", clusterName)

		adminPassword := identity.AdminPassword

		// Adds remotedesktop feature on master
		feat, err := features.NewEmbeddedFeature(task, "remotedesktop")
		if err != nil {
			return err
		}
		results, err := feat.Add(c, data.Map{
			"Username": "cladm",
			"Password": adminPassword,
		}, resources.InstallSettings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}

// install proxycache-client feature if not disabled
func (c *cluster) installProxyCacheClient(task concurrency.Task, pbHost *protocol.Host, hostLabel string) (err error) {
	if pbHost == nil {
		return scerr.InvalidParameterError("pbHost", "cannot be nil")
	}
	if hostLabel == "" {
		return scerr.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	disabled := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
			featuresv1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	if !disabled {
		feat, err := features.NewFeature(task, "proxycache-client")
		if err != nil {
			return err
		}
		results, err := feature.Add(c, data.Map{}, resources.InstallSettings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[%s] failed to install feature 'proxycache-client': %s", hostLabel, msg)
		}
	}
	return nil
}

// install proxycache-server feature if not disabled
func (c *cluster) installProxyCacheServer(task concurrency.Task, pbHost *protocol.Host, hostLabel string) (err error) {

	if pbHost == nil {
		return scerr.InvalidParameterError("pbHost", "cannot be nil")
	}
	if hostLabel == "" {
		return scerr.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	disabled := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialier.JSONProperties) error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
			featuresv1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	if err != nil {
		return err
	}
	if !disabled {
		feat, err := features.NewEmbeddedFeature(task, "proxycache-server")
		if err != nil {
			return err
		}
		results, err := feat.Add(c, data.Map{}, resources.InstallSettings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[%s] failed to install feature 'proxycache-server': %s", hostLabel, msg)
		}
	}
	return nil
}

// intallDocker installs docker and docker-compose
func (c *cluster) installDocker(task concurrency.Task, pbHost *protocol.Host, hostLabel string) (err error) {
	if pbHost == nil {
		return scerr.InvalidParameterError("pbHost", "cannot be nil")
	}
	if hostLabel == "" {
		return scerr.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	feat, err := features.NewEmbeddedFeature(task, "docker")
	if err != nil {
		return err
	}
	results, err := feat.Add(c, data.Map{}, resources.InstallSettings{})
	if err != nil {
		return err
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		logrus.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, msg)
		return fmt.Errorf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, msg)
	}
	logrus.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (c *cluster) buildHostname(task concurrency.Task, core string, nodeType NodeType.Enum) (cluid string, err error) {
	var index int

	defer scerr.OnPanic(&err)()

	// Locks for write the manager extension...

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			// FIXME: validate cast
			nodesV2 := clonable.(*propertiesv2.Nodes)
			switch nodeType {
			case NodeType.Node:
				nodesV2.PrivateLastIndex++
				index = nodesV2.PrivateLastIndex
			case NodeType.Master:
				nodesV2.MasterLastIndex++
				index = nodesV2.MasterLastIndex
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return c.Identity(task).Name + "-" + core + "-" + strconv.Itoa(index), nil
}

func handleExecuteScriptReturn(retcode int, stdout string, stderr string, err error, msg string) error {
	if retcode == 0 {
		return nil
	}

	var collected []string
	if stdout != "" {
		errLines := strings.Split(stdout, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}
	if stderr != "" {
		errLines := strings.Split(stderr, "\n")
		for _, errline := range errLines {
			if strings.Contains(errline, "An error occurred") {
				collected = append(collected, errline)
			}
		}
	}

	if len(collected) > 0 {
		if err != nil {
			return scerr.Wrap(err, fmt.Sprintf("%s: std error [%s]", msg, collected))
		}
		return fmt.Errorf("%s: std error [%s]", msg, strings.Join(collected, ";"))
	}

	return nil
}
/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package operations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate rice embed-go

const featureFileExt = ".yml"

var (
	templateBox *rice.Box
	// emptyParams = map[string]interface{}{}

	availableEmbeddedFeaturesMap = map[installmethod.Enum]map[string]*Feature{}
	allEmbeddedFeaturesMap       = map[string]*Feature{}
	allEmbeddedFeatures          []*Feature
)

func getSHA256Hash(text string) string {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// loadSpecFile returns the content of the spec file of the feature named 'name'
func loadSpecFile(name string) (string, *viper.Viper, error) {
	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("../operations/embeddedfeatures")
		err = debug.InjectPlannedError(err)
		if err != nil {
			return "", nil, fail.Wrap(err, "failed to open embedded feature specification MetadataFolder")
		}
	}
	name += featureFileExt
	tmplString, err := templateBox.String(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", nil, fail.Wrap(err, "failed to read embedded feature specification file '%s'", name)
	}

	logrus.Debugf("loaded feature %s:SHA256:%s", name, getSHA256Hash(tmplString))

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", nil, fail.Wrap(err, "syntax error in feature specification file '%s'", name)
	}

	// Validating content...
	if !v.IsSet("feature") {
		return "", nil, fail.SyntaxError("feature specification file '%s' must begin with 'feature:'", name)
	}
	if !v.IsSet("feature.install") {
		return "", nil, fail.SyntaxError("syntax error in feature specification file '%s': missing 'install'", name)
	}
	if len(v.GetStringMap("feature.install")) == 0 {
		return "", nil, fail.SyntaxError("syntax error in feature specification file '%s': 'install' defines no method", name)
	}
	return name, v, nil
}

// dockerFeature ...
func dockerFeature() *Feature {
	name := "docker"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// dockerSwarmFeature ...
func dockerSwarmFeature() *Feature {
	name := "docker-swarm"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ntpServerFeature ...
func ntpServerFeature() *Feature {
	name := "ntpserver"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ntpServerFeature ...
func ntpClientFeature() *Feature {
	name := "ntpclient"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ansibleFeature from official repos ...
func ansibleFeature() *Feature {
	name := "ansible"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// certificateAuthorityFeature from official repos ...
func certificateAuthorityFeature() *Feature {
	name := "certificateauthority"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// postgresql4platformFeature feature. ...
func postgresql4platformFeature() *Feature {
	name := "postgresql4platform"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// nVidiaDockerFeature ...
func nVidiaDockerFeature() *Feature {
	name := "nvidiadocker"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// kubernetesFeature ...
func kubernetesFeature() *Feature {
	name := "kubernetes"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// helm2Feature ...
func helm2Feature() *Feature {
	name := "helm2"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// helm3Feature ...
func helm3Feature() *Feature {
	name := "helm3"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// sparkmaster4platformFeature ...
func sparkmaster4platformFeature() *Feature {
	name := "sparkmaster4platform"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// remoteDesktopFeature ...
func remoteDesktopFeature() *Feature {
	name := "remotedesktop"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// proxycacheServerFeature ...
func proxycacheServerFeature() *Feature {
	name := "proxycache-server"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// proxycacheClientFeature ...
func proxycacheClientFeature() *Feature {
	name := "proxycache-client"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// postgres4gatewayFeature ...
func postgres4gatewayFeature() *Feature {
	name := "postgres4gateway"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// edgeproxy4subnetFeature ...
func edgeproxy4subnetFeature() *Feature {
	name := "edgeproxy4subnet"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// keycloak4platformFeature ...
func keycloak4platformFeature() *Feature {
	name := "keycloak4platform"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// monitoring4platformFeature ...
func monitoring4platformFeature() *Feature {
	name := "monitoring4platform"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// NOTE: init() moved in zinit.go, to be sure the init() of rice-box.go is called first

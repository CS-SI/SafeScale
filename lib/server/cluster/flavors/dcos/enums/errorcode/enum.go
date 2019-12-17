/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package errorcode

import (
	"fmt"
	"strings"
)

type Enum int

const (
	_ Enum = iota

	DcosInstallDownload
	DcosInstallExecution
	DcosConfigGeneratorDownload
	DcosGenerateConfig
	DcosCliDownload
	DockerNginxDownload
	DockerNginxStart
	DockerProxyBuild
	DockerProxyStart
	DockerGuacamoleBuild
	DockerPyInstall
	DockerInstall
	DockerComposeDownload
	DockerComposeConfig
	DockerComposeExecution
	DesktopInstall
	DesktopStart
	DesktopTimeout
	GuacamoleImageDownload
	KubectlDownload
	SystemUpdate
	ToolsInstall
	PipInstall

	//NextErrorCode is the next error code usable
	NextErrorCode
)

var (
	StringMap = map[string]Enum{
		"DcosInstallDownload":         DcosInstallDownload,
		"DcosInstallExecution":        DcosInstallExecution,
		"DcosConfigGeneratorDownload": DcosConfigGeneratorDownload,
		"DcosGenerateConfig":          DcosGenerateConfig,
		"DcosCliDownload":             DcosCliDownload,
		"DockerNginxDownload":         DockerNginxDownload,
		"DockerNginxStart":            DockerNginxStart,
		"DockerProxyBuild":            DockerProxyBuild,
		"DockerProxyStart":            DockerProxyStart,
		"DockerGuacamoleBuild":        DockerGuacamoleBuild,
		"DockerPyInstall":             DockerPyInstall,
		"DockerInstall":               DockerInstall,
		"DockerComposeDownload":       DockerComposeDownload,
		"DockerComposeConfig":         DockerComposeConfig,
		"DockerComposeExecution":      DockerComposeExecution,
		"DesktopInstall":              DesktopInstall,
		"DesktopStart":                DesktopStart,
		"DesktopTimeout":              DesktopTimeout,
		"GuacamoleImageDownload":      GuacamoleImageDownload,
		"KubectlDownload":             KubectlDownload,
		"SystemUpdate":                SystemUpdate,
		"ToolsInstall":                ToolsInstall,
		"PipInstall":                  PipInstall,
	}

	enumMap = map[Enum]string{
		DcosInstallDownload:         "DcosInstallDownload",
		DcosInstallExecution:        "DcosInstallExecution",
		DcosConfigGeneratorDownload: "DcosConfigGeneratorDownload",
		DcosGenerateConfig:          "DcosGenerateConfig",
		DcosCliDownload:             "DcosCliDownload",
		DockerNginxDownload:         "DockerNginxDownload",
		DockerNginxStart:            "DockerNginxStart",
		DockerProxyBuild:            "DockerProxyBuild",
		DockerProxyStart:            "DockerProxyStart",
		DockerGuacamoleBuild:        "DockerGuacamoleBuild",
		DockerPyInstall:             "DockerPyInstall",
		DockerInstall:               "DockerInstall",
		DockerComposeDownload:       "DockerComposeDownload",
		DockerComposeConfig:         "DockerComposeConfig",
		DockerComposeExecution:      "DockerComposeExecution",
		DesktopInstall:              "DesktopInstall",
		DesktopStart:                "DesktopStart",
		DesktopTimeout:              "DesktopTimeout",
		GuacamoleImageDownload:      "GuacamoleImageDownload",
		KubectlDownload:             "KubectlDownload",
		SystemUpdate:                "SystemUpdate",
		ToolsInstall:                "ToolsInstall",
		PipInstall:                  "PipInstall",
	}
)

// Parse returns a Enum corresponding to the string parameter
// If the string doesn't correspond to any Enum, returns an error (nil otherwise)
// This function is intended to be used to parse user input.
func Parse(v string) (Enum, error) {
	var (
		e  Enum
		ok bool
	)
	lowered := strings.ToLower(v)
	if e, ok = StringMap[lowered]; !ok {
		return e, fmt.Errorf("failed to find a Flavor matching with '%s'", v)
	}
	return e, nil

}

// String returns a string representation of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	panic(fmt.Sprintf("failed to find a string matching with Flavor '%d'!", e))
}

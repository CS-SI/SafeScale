//go:build integration
// +build integration

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests"
	"github.com/CS-SI/SafeScale/v22/integrationtests/enums/providers"
)

func Test_Docker(t *testing.T) {
	integrationtests.Docker(t, providers.OVH)
}

func Test_DockerNotGateway(t *testing.T) {
	integrationtests.DockerNotGateway(t, providers.OVH)
}

func Test_DockerCompose(t *testing.T) {
	integrationtests.DockerCompose(t, providers.OVH)
}

func Test_RemoteDesktop(t *testing.T) {
	integrationtests.RemoteDesktop(t, providers.OVH)
}

func Test_ReverseProxy(t *testing.T) {
	integrationtests.ReverseProxy(t, providers.OVH)
}

func Test_NvidiaDocker(t *testing.T) {
	integrationtests.NvidiaDocker(t, providers.OVH)
}

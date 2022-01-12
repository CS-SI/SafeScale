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

package test

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Basic(t *testing.T) {
	integrationtests.Basic(t, providers.CLOUDFERRO)
}
func Test_ReadyToSsh(t *testing.T) {
	integrationtests.ReadyToSSH(t, providers.CLOUDFERRO)
}

func Test_ShareError(t *testing.T) {
	integrationtests.ShareError(t, providers.CLOUDFERRO)
}

func Test_VolumeError(t *testing.T) {
	integrationtests.VolumeError(t, providers.CLOUDFERRO)
}

func Test_StopStart(t *testing.T) {
	integrationtests.StopStart(t, providers.CLOUDFERRO)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	integrationtests.DeleteVolumeMounted(t, providers.CLOUDFERRO)
}

func Test_UntilShare(t *testing.T) {
	integrationtests.UntilShare(t, providers.CLOUDFERRO)
}

func Test_UntilVolume(t *testing.T) {
	integrationtests.UntilVolume(t, providers.CLOUDFERRO)
}

//go:build integrationtests

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

package integrationtests_ng

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests-ng/helpers"

	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/buckets"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/clusters"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/features"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/hosts"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/networks"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/securitygroups"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/shares"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/subnets"
	_ "github.com/CS-SI/SafeScale/v22/integrationtests-ng/resources/volumes"
)

func Test_All(t *testing.T) {
	helpers.RunScenarios(t)
}

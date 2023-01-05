//go:build ignore && (allintegration || integration)
// +build ignore
// +build allintegration integration

/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package helpers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRunJq(t *testing.T) {
	mirrors := "{\"result\":[{\"description\":\"SG for hosts with public IP in Subnet clarify of Network clarify\",\"id\":\"1df0f421-1714-460c-b2ac-72e597ce8aed\",\"name\":\"safescale-sg_subnet_publicip.clarify.clarify\"},{\"description\":\"SG for internal access in Subnet sgtest-network-1 of Network sgtest-network-1\",\"id\":\"888bfac6-b9d9-4a23-88ff-a2c3a6d37121\",\"name\":\"safescale-sg_subnet_internals.sgtest-network-1.sgtest-network-1\"},{\"description\":\"SG for internal access in Subnet clarify of Network clarify\",\"id\":\"a6e675ea-7184-4828-b503-625f4ea2a5ff\",\"name\":\"safescale-sg_subnet_internals.clarify.clarify\"},{\"description\":\"SG for gateways in Subnet sgtest-network-1 of Network sgtest-network-1\",\"id\":\"a795bd19-a872-47ff-9987-4bcd890c5569\",\"name\":\"safescale-sg_subnet_gateways.sgtest-network-1.sgtest-network-1\"},{\"description\":\"SG for gateways in Subnet clarify of Network clarify\",\"id\":\"f034e23b-2557-43e1-81df-e61a0c8e0301\",\"name\":\"safescale-sg_subnet_gateways.clarify.clarify\"},{\"description\":\"SG for hosts with public IP in Subnet sgtest-network-1 of Network sgtest-network-1\",\"id\":\"f50ce1ea-8af4-4537-95f7-8d1adad631aa\",\"name\":\"safescale-sg_subnet_publicip.sgtest-network-1.sgtest-network-1\"}],\"status\":\"success\"}"

	x, err := RunJq(mirrors, ".result[1].description")
	assert.Nil(t, err)
	assert.NotNil(t, x)
	assert.Contains(t, x, "sgtest")
}

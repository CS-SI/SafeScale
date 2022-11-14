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

package ovhtf

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

func (p *provider) CreateHost(ctx context.Context, request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ClearHostStartupScript(ctx context.Context, parameter iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) InspectHost(ctx context.Context, parameter iaasapi.HostParameter) (*abstract.HostFull, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) GetHostState(ctx context.Context, parameter iaasapi.HostParameter) (hoststate.Enum, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ListHosts(ctx context.Context, b bool) (abstract.HostList, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) DeleteHost(ctx context.Context, parameter iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) StopHost(ctx context.Context, host iaasapi.HostParameter, gracefully bool) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) StartHost(ctx context.Context, parameter iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) RebootHost(ctx context.Context, parameter iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ResizeHost(ctx context.Context, parameter iaasapi.HostParameter, requirements abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) WaitHostReady(ctx context.Context, hostParam iaasapi.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) BindSecurityGroupToHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) UnbindSecurityGroupFromHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ConsolidateHostSnippet(ahc *abstract.HostCore) {
	if valid.IsNil(p) || ahc == nil {
		return
	}

	_ = ahc.AddOptions(abstract.UseTerraformSnippet(networkDesignResourceSnippetPath))
}

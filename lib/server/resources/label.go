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

package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// DISABLED go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/resources.Label -o mocks/mock_label.go

// Label links Object Storage folder and getTags
type Label interface {
	Metadata
	data.Identifiable

	BindToHost(ctx context.Context, hostInstance Host, value string) fail.Error               // instructs Label to be bound to Host with overrided value (if not a Tag)
	Browse(ctx context.Context, callback func(*abstract.Label) fail.Error) fail.Error         // walks through all the metadata objects in labels
	Create(ctx context.Context, name string, hasDefault bool, defaultValue string) fail.Error // creates a Label
	Delete(ctx context.Context) fail.Error                                                    // deletes a Label
	IsTag(ctx context.Context) (bool, fail.Error)                                             // tells if the label is a Tag (ie a Label that does not carry a value)
	DefaultValue(ctx context.Context) (string, fail.Error)                                    // returns the default value of the Label
	ToProtocol(ctx context.Context) (*protocol.LabelInspectResponse, fail.Error)              // converts Label to equivalent protocol message
	UnbindFromHost(ctx context.Context, hostInstance Host) fail.Error                         // instructs Label to unbind Host from it
}

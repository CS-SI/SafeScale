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
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// DISABLED go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/resources.Tag -o mocks/mock_tag.go

// Tag links Object Storage folder and getTags
type Tag interface {
	Metadata
	data.Identifiable
	observer.Observable

	Browse(ctx context.Context, callback func(*abstract.Tag) fail.Error) fail.Error // walks through all the metadata objects in network
	Create(ctx context.Context, req abstract.TagRequest) fail.Error                 // creates a tag
	Delete(ctx context.Context) fail.Error                                          // deletes a tag
	ToProtocol(ctx context.Context) (*protocol.TagInspectResponse, fail.Error)      // converts tag to equivalent protocol message
}

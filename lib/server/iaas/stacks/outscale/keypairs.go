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

package outscale

import (
	"context"
	"encoding/base64"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(ctx context.Context, name string) (akp *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	var xerr fail.Error
	akp, xerr = abstract.NewKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}
	return akp, s.ImportKeyPair(ctx, akp)
}

// ImportKeyPair is used to import an existing KeyPair in Outscale
func (s stack) ImportKeyPair(ctx context.Context, keypair *abstract.KeyPair) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keyair", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale"), "'%s')", keypair.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcCreateKeypair(ctx, keypair.Name, base64.StdEncoding.EncodeToString([]byte(keypair.PublicKey)))
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(ctx context.Context, id string) (akp *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale"), "'%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadKeypairByName(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	kp := abstract.KeyPair{
		ID:   resp.KeypairName,
		Name: resp.KeypairName,
	}
	return &kp, nil
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadKeypairs(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}

	var kps []*abstract.KeyPair
	for _, kp := range resp {
		kps = append(kps, &abstract.KeyPair{
			ID:   kp.KeypairName,
			Name: kp.KeypairName,
		})
	}
	return kps, nil

}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale"), "'%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteKeypair(ctx, id)
}

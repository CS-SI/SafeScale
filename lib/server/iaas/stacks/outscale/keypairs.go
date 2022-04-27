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
	"encoding/base64"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(name string) (akp *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	var xerr fail.Error
	akp, xerr = abstract.NewKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}
	return akp, s.ImportKeyPair(akp)
}

// ImportKeyPair is used to import an existing KeyPair in Outscale
func (s stack) ImportKeyPair(keypair *abstract.KeyPair) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keyair", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", keypair.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcCreateKeypair(keypair.Name, base64.StdEncoding.EncodeToString([]byte(keypair.PublicKey)))
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(id string) (akp *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadKeypairByName(id)
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
func (s stack) ListKeyPairs() (_ []*abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadKeypairs(nil)
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
func (s stack) DeleteKeyPair(name string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteKeypair(name)
}

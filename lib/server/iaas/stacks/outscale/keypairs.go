/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(name string) (akp *abstract.KeyPair, xerr fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAKP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	akp, xerr = abstract.NewKeyPair(name)
	if xerr != nil {
		return nullAKP, xerr
	}
	return akp, s.ImportKeyPair(akp)
}

// ImportKeyPair is used to import an existing KeyPair in Outscale
func (s stack) ImportKeyPair(keypair *abstract.KeyPair) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keyair", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", keypair.Name).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	return s.rpcCreateKeypair(keypair.Name, base64.StdEncoding.EncodeToString([]byte(keypair.PublicKey)))
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(id string) (akp *abstract.KeyPair, xerr fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAKP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadKeypairByName(id)
	if xerr != nil {
		return nullAKP, xerr
	}

	kp := abstract.KeyPair{
		ID:   resp.KeypairName,
		Name: resp.KeypairName,
	}
	return &kp, nil
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs() (_ []abstract.KeyPair, xerr fail.Error) {
	var emptySlice []abstract.KeyPair
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadKeypairs(nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	var kps []abstract.KeyPair
	for _, kp := range resp {
		kps = append(kps, abstract.KeyPair{
			ID:   kp.KeypairName,
			Name: kp.KeypairName,
		})
	}
	return kps, nil

}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(name string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "'%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	return s.rpcDeleteKeypair(name)
}

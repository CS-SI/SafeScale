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
	"fmt"

	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	createKeypairOpts := osc.CreateKeypairOpts{
		CreateKeypairRequest: optional.NewInterface(osc.CreateKeypairRequest{
			KeypairName: keypair.Name,
			PublicKey:   base64.StdEncoding.EncodeToString([]byte(keypair.PublicKey)),
		}),
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.KeypairApi.CreateKeypair(s.auth, &createKeypairOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readKeypairsOpts := osc.ReadKeypairsOpts{
		ReadKeypairsRequest: optional.NewInterface(osc.ReadKeypairsRequest{
			Filters: osc.FiltersKeypair{
				KeypairNames: []string{id},
			},
		}),
	}
	var resp osc.ReadKeypairsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.KeypairApi.ReadKeypairs(s.auth, &readKeypairsOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAKP, xerr
	}
	if len(resp.Keypairs) > 1 {
		return nullAKP, fail.InconsistentError("Inconsistent provider response")
	}
	if len(resp.Keypairs) == 0 {
		return nullAKP, fail.NotFoundError(fmt.Sprintf("Keypair %s not found", id))
	}
	kp := resp.Keypairs[0]
	return &abstract.KeyPair{
		ID:   kp.KeypairName,
		Name: kp.KeypairName,
	}, nil
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs() (_ []abstract.KeyPair, xerr fail.Error) {
	var emptySlice []abstract.KeyPair
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	var resp osc.ReadKeypairsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.KeypairApi.ReadKeypairs(s.auth, nil)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	var kps []abstract.KeyPair
	for _, kp := range resp.Keypairs {
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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	deleteKeypairOpts := osc.DeleteKeypairOpts{
		DeleteKeypairRequest: optional.NewInterface(osc.DeleteKeypairRequest{
			KeypairName: name,
		}),
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.KeypairApi.DeleteKeypair(s.auth, &deleteKeypairOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

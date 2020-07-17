/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (akp *abstract.KeyPair, xerr fail.Error) {
	nullAkp := &abstract.KeyPair{}
	if s == nil {
		return nullAkp, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAkp, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	akp, xerr = abstract.NewKeyPair(name)
	if xerr != nil {
		return nullAkp, xerr
	}
	return akp, s.ImportKeyPair(akp)
}

// ImportKeyPair is used to import an existing KeyPair in Outscale
func (s *Stack) ImportKeyPair(keypair *abstract.KeyPair) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keyair", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "'%s')", keypair.Name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	createKeypairRequest := osc.CreateKeypairRequest{
		KeypairName: keypair.Name,
		PublicKey:   base64.StdEncoding.EncodeToString([]byte(keypair.PublicKey)),
	}
	_, _, err := s.client.KeypairApi.CreateKeypair(s.auth, &osc.CreateKeypairOpts{
		CreateKeypairRequest: optional.NewInterface(createKeypairRequest),
	})
	return normalizeError(err)
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (akp *abstract.KeyPair, xerr fail.Error) {
	nullAkp := &abstract.KeyPair{}
	if s == nil {
		return nullAkp, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAkp, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "'%s')", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readKeypairsRequest := osc.ReadKeypairsRequest{Filters: osc.FiltersKeypair{
		KeypairNames: []string{id},
	}}
	resp, _, err := s.client.KeypairApi.ReadKeypairs(s.auth, &osc.ReadKeypairsOpts{
		ReadKeypairsRequest: optional.NewInterface(readKeypairsRequest),
	})
	if err != nil {
		return nullAkp, normalizeError(err)
	}
	if len(resp.Keypairs) > 1 {
		return nullAkp, fail.InconsistentError("Inconsistent provider response")
	}
	if len(resp.Keypairs) == 0 {
		return nullAkp, fail.NotFoundError(fmt.Sprintf("Keypair %s not found", id))
	}
	kp := resp.Keypairs[0]
	return &abstract.KeyPair{
		ID:   kp.KeypairName,
		Name: kp.KeypairName,
	}, nil
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() (_ []abstract.KeyPair, xerr fail.Error) {
	nullList := make([]abstract.KeyPair, 0)
	if s == nil {
		return nullList, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	resp, _, err := s.client.KeypairApi.ReadKeypairs(s.auth, nil)
	if err != nil {
		return nullList, normalizeError(err)
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
func (s *Stack) DeleteKeyPair(name string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "'%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	deleteKeypairRequest := osc.DeleteKeypairRequest{
		KeypairName: name,
	}
	_, _, err := s.client.KeypairApi.DeleteKeypair(s.auth, &osc.DeleteKeypairOpts{
		DeleteKeypairRequest: optional.NewInterface(deleteKeypairRequest),
	})
	return normalizeError(err)
}

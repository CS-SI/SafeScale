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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/outscale/osc-sdk-go/oapi"
	"golang.org/x/crypto/ssh"
)

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%s)", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey
	pub, _ := ssh.NewPublicKey(&publicKey)
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	pubKey := string(pubBytes)

	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	priKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBytes,
		},
	)
	priKey := string(priKeyPem)
	_, err := s.client.POST_CreateKeypair(oapi.CreateKeypairRequest{
		KeypairName: name,
		PublicKey:   base64.StdEncoding.EncodeToString(pubBytes),
	})
	if err != nil {
		return nil, err
	}
	//kp.OK.Keypair.
	//_ = ioutil.WriteFile("/tmp/key.pem", []byte(kp.OK.Keypair.PrivateKey), 0700)

	return &resources.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil

}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}
	resp, err := s.client.POST_ReadKeypairs(oapi.ReadKeypairsRequest{Filters: oapi.FiltersKeypair{
		KeypairNames: []string{id},
	}})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.OK == nil || len(resp.OK.Keypairs) > 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	if len(resp.OK.Keypairs) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("Keypair %s not found", id))
	}
	kp := resp.OK.Keypairs[0]
	return &resources.KeyPair{
		ID:   kp.KeypairName,
		Name: kp.KeypairName,
	}, nil
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	resp, err := s.client.POST_ReadKeypairs(oapi.ReadKeypairsRequest{})
	if err != nil {
		return nil, err
	}
	var kps []resources.KeyPair
	for _, kp := range resp.OK.Keypairs {
		kps = append(kps, resources.KeyPair{
			ID:   kp.KeypairName,
			Name: kp.KeypairName,
		})
	}
	return kps, nil

}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}
	_, err := s.client.POST_DeleteKeypair(oapi.DeleteKeypairRequest{
		KeypairName: id,
	})
	return err
}

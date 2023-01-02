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

package sshtunnel

import (
	"fmt"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"golang.org/x/crypto/ssh"
)

// Syntactic sugar for Endpoint abstraction (Entrypoint, SSHJump, Endpoint)

type Endpoint struct {
	user           string
	host           string
	port           int
	authentication []ssh.AuthMethod
}

type Entrypoint = Endpoint
type SSHJump = Endpoint

type EndpointOption func(tunnel *Endpoint) error

func (endpoint Endpoint) Validate() error {
	return validation.ValidateStruct(&endpoint,
		validation.Field(&endpoint.user, is.Alphanumeric),              // "^[a-zA-Z0-9]+$"
		validation.Field(&endpoint.host, validation.Required, is.Host), // net.ParseIP and `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`
		validation.Field(&endpoint.port, validation.Min(0), validation.Max(65535)),
	)
}

func EndpointOptionAuth(auth ssh.AuthMethod) EndpointOption {
	return func(endp *Endpoint) error {
		endp.authentication = append(endp.authentication, auth)
		return nil
	}
}

func EndpointOptionPassword(pass string) EndpointOption {
	return func(endp *Endpoint) error {
		endp.authentication = append(endp.authentication, ssh.Password(pass))
		return nil
	}
}

func EndpointOptionKeyFromString(key string, passphrase string) EndpointOption {
	return func(endp *Endpoint) error {
		publicKey, err := AuthMethodFromPrivateKey([]byte(key), []byte(passphrase))
		if err != nil {
			return err
		}
		endp.authentication = append(endp.authentication, publicKey)
		return nil
	}
}

func EndpointOptionKeyFromFile(filename, passphrase string) EndpointOption {
	return func(endp *Endpoint) error {
		pk, err := AuthMethodFromPrivateKeyFile(filename, []byte(passphrase))
		if err != nil {
			return err
		}
		endp.authentication = append(endp.authentication, pk)
		return nil
	}
}

func NewEndpoint(s string, options ...EndpointOption) (_ *Endpoint, err error) {
	defer OnPanic(&err)

	endpoint := &Endpoint{}
	host := s

	if parts := strings.Split(s, "@"); len(parts) > 1 {
		endpoint.user = parts[0]
		endpoint.host = parts[1]
		host = endpoint.host
	}

	if parts := strings.Split(host, ":"); len(parts) > 1 {
		endpoint.host = parts[0]
		endpoint.port, err = strconv.Atoi(parts[1])
		if err != nil {
			return &Endpoint{}, fmt.Errorf("invalid: invalid port: %w", err)
		}
	}

	for _, opt := range options {
		if opt != nil {
			err = opt(endpoint)
			if err != nil {
				return &Endpoint{}, err
			}
		}
	}

	err = endpoint.Validate()
	if err != nil {
		return &Endpoint{}, err
	}

	return endpoint, err
}

func (endpoint Endpoint) Address() string {
	return fmt.Sprintf("%s:%d", endpoint.host, endpoint.port)
}

func (endpoint Endpoint) User() string {
	return endpoint.user
}

func (endpoint Endpoint) Host() string {
	return endpoint.host
}

func (endpoint Endpoint) Port() int {
	return endpoint.port
}

func (endpoint Endpoint) Authentication() []ssh.AuthMethod {
	return endpoint.authentication
}

func (endpoint Endpoint) String() string {
	if endpoint.user != "" {
		return fmt.Sprintf("%s@%s:%d", endpoint.user, endpoint.host, endpoint.port)
	}
	return fmt.Sprintf("%s:%d", endpoint.host, endpoint.port)
}

func (endpoint Endpoint) Dump() string {
	if endpoint.user != "" {
		return fmt.Sprintf("%s@%s:%d", endpoint.user, endpoint.host, endpoint.port)
	}
	return fmt.Sprintf("%s:%d", endpoint.host, endpoint.port)
}

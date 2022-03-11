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

package objectstorage

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewLocation(t *testing.T) {

	cfg := Config{
		Type:         "s3",
		EnvAuth:      false,
		AuthVersion:  1,
		EndpointType: "EndpointType",
		Endpoint:     "http://localhost:9000",
		User:         "admin",
		SecretKey:    "password",
	}
	loc, err := NewLocation(cfg)
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.location")
	require.EqualValues(t, err, nil)

}

func TestLocation_IsNull(t *testing.T) {

	var nilLoc *location = nil
	require.EqualValues(t, nilLoc.IsNull(), true)

	cfg := Config{
		Type:         "s3",
		EnvAuth:      false,
		AuthVersion:  1,
		EndpointType: "EndpointType",
		Endpoint:     "http://localhost:9000",
		User:         "admin",
		SecretKey:    "password",
	}
	loc, err := NewLocation(cfg)
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.location")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, loc.IsNull(), false)

}

func TestLocation_Connect(t *testing.T) {

	var nilLoc *location = nil
	err := nilLoc.connect()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")

	cfg := Config{
		Type:         "s3",
		EnvAuth:      false,
		AuthVersion:  1,
		EndpointType: "EndpointType",
		Endpoint:     "http://localhost:9000",
		User:         "admin",
		SecretKey:    "password",
	}
	loc, err := NewLocation(cfg)
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.location")
	require.EqualValues(t, err, nil)

	err = loc.connect()
	require.EqualValues(t, err, nil)

}

func TestLocation_Protocol(t *testing.T) {

	cfg := Config{
		Type:         "s3",
		EnvAuth:      false,
		AuthVersion:  1,
		EndpointType: "EndpointType",
		Endpoint:     "http://localhost:9000",
		User:         "admin",
		SecretKey:    "password",
	}
	loc, err := NewLocation(cfg)
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.location")
	require.EqualValues(t, err, nil)

	c, err := loc.Protocol()
	require.EqualValues(t, c, "s3")
	require.EqualValues(t, err, nil)

}

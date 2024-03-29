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

package objectstorage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func minioIsRunning() (bool, error) {
	value, ok := os.LookupEnv("MINIO_HEALTH_ENDPOINT")
	if !ok {
		// putting in place previous env variable is responsibility of the script running the tests (or DOCKER env, or GitHub Action, etc.) or needs to be tailored by the developer to fit dev environment
		value = "http://localhost:9000/minio/health/live"
	}

	// See https://docs.min.io/minio/baremetal/monitoring/healthcheck-probe.html
	resp, err := http.Get(value) // nolint
	if err != nil {
		return false, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	good := false

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failure: it seems something went wrong starting minio in: %s", value)
	}

	for k, v := range resp.Header {
		if k == "Server" {
			for _, vals := range v {
				if strings.Contains(vals, "MinIO") {
					good = true
					break
				}
			}
		}
	}

	if !good {
		return false, fmt.Errorf("failure: it seems minio is not running in: %s", value)
	}

	return true, nil
}

func Test_NewLocation(t *testing.T) {
	good, err := minioIsRunning()
	if !good {
		t.Log("Test require Minio started")
		t.Skip()
	}
	require.Nil(t, err)

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
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.locationcache")
	require.Nil(t, err)

}

func TestLocation_IsNull(t *testing.T) {
	good, err := minioIsRunning()
	if !good {
		t.Log("Test require Minio started")
		t.Skip()
	}
	require.Nil(t, err)

	var nilLoc *location = nil
	require.True(t, nilLoc.IsNull())

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
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.locationcache")
	require.Nil(t, err)
}

func TestLocation_Connect(t *testing.T) {
	good, err := minioIsRunning()
	if !good {
		t.Log("Test require Minio started")
		t.Skip()
	}
	require.Nil(t, err)

	var nilLoc *location = nil
	err = nilLoc.connect()
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
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.locationcache")
	require.Nil(t, err)
}

func TestLocation_Protocol(t *testing.T) {
	good, err := minioIsRunning()
	if !good {
		t.Log("Test require Minio started")
		t.Skip()
	}
	require.Nil(t, err)

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
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.locationcache")
	require.Nil(t, err)

	c, err := loc.Protocol()
	require.EqualValues(t, c, "s3")
	require.Nil(t, err)

}

func TestLocation_CreateBucket(t *testing.T) {
	good, err := minioIsRunning()
	if !good {
		t.Log("Test require Minio started")
		t.Skip()
	}
	require.Nil(t, err)

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
	require.EqualValues(t, reflect.TypeOf(loc).String(), "*objectstorage.locationcache")
	require.Nil(t, err)

	if there, err := loc.FindBucket(context.Background(), "boo"); err == nil {
		if there {
			return
		}
	}

	osb, err := loc.CreateBucket(context.Background(), "boo")
	require.Nil(t, err)
	require.NotNil(t, osb)
}

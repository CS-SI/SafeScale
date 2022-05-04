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

package temporal

import (
	"reflect"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
)

func Test_NewTimings(t *testing.T) {
	result := NewTimings()
	require.EqualValues(t, reflect.TypeOf(result).String(), "*temporal.MutableTimings")
}

func Test_NewTimingsToml(t *testing.T) {
	result := NewTimings()
	ct, err := result.ToToml()
	require.Nil(t, err)
	t.Logf(ct)
}

func Test_CarryAfterYou(t *testing.T) {
	type Foo struct {
		Thing MutableTimings
	}

	deepest := &Foo{
		Thing: *NewTimings(),
	}

	barr, err := toml.Marshal(deepest)
	require.Nil(t, err)

	t.Logf(string(barr))
}

func TestMutableTimings_ContextTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.ContextTimeout(), 60*time.Second)

	mt = NewTimings()
	mt.Timeouts.Context = 42 * time.Second
	require.EqualValues(t, mt.ContextTimeout(), 42*time.Second)

}

func TestMutableTimings_ConnectionTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.ConnectionTimeout(), 60*time.Second)

	mt = NewTimings()
	mt.Timeouts.Connection = 42 * time.Second
	require.EqualValues(t, mt.ConnectionTimeout(), 42*time.Second)

}

func TestMutableTimings_ExecutionTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.ExecutionTimeout(), 8*time.Minute)

	mt = NewTimings()
	mt.Timeouts.Operation = 42 * time.Second
	require.EqualValues(t, mt.ExecutionTimeout(), 42*time.Second)

}

func TestMutableTimings_OperationTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.OperationTimeout(), 150*time.Second)

	mt = NewTimings()
	mt.Timeouts.Operation = 42 * time.Second
	require.EqualValues(t, mt.OperationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostCreationTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.HostCreationTimeout(), 8*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostCreation = 42 * time.Second
	require.EqualValues(t, mt.HostCreationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostCleanupTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.HostOperationTimeout(), 2*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostOperation = 42 * time.Second
	require.EqualValues(t, mt.HostOperationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostOperationTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.HostOperationTimeout(), 2*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostOperation = 42 * time.Second
	require.EqualValues(t, mt.HostOperationTimeout(), 42*time.Second)

}

func TestMutableTimings_CommunicationTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.CommunicationTimeout(), 3*time.Minute)

	mt = NewTimings()
	mt.Timeouts.Communication = 42 * time.Second
	require.EqualValues(t, mt.CommunicationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostLongOperationTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.HostLongOperationTimeout(), 14*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostLongOperation = 42 * time.Second
	require.EqualValues(t, mt.HostLongOperationTimeout(), 42*time.Second)

}

func TestMutableTimings_SSHConnectionTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.SSHConnectionTimeout(), 3*time.Minute)

	mt = NewTimings()
	mt.Timeouts.SSHConnection = 42 * time.Second
	require.EqualValues(t, mt.SSHConnectionTimeout(), 42*time.Second)

}

func TestMutableTimings_MetadataTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.MetadataTimeout(), 150*time.Second)

	mt = NewTimings()
	mt.Timeouts.Metadata = 42 * time.Second
	require.EqualValues(t, mt.MetadataTimeout(), 42*time.Second)

}

func TestMutableTimings_MetadataReadAfterWriteTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.MetadataReadAfterWriteTimeout(), 90*time.Second)

	mt = NewTimings()
	mt.Timeouts.MetadataReadAfterWrite = 42 * time.Second
	require.EqualValues(t, mt.MetadataReadAfterWriteTimeout(), 42*time.Second)

}

func TestMutableTimings_SmallDelay(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.SmallDelay(), 1*time.Second)

	mt = NewTimings()
	mt.Delays.Small = 42 * time.Second
	require.EqualValues(t, mt.SmallDelay(), 42*time.Second)

}

func TestMutableTimings_NormalDelay(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.NormalDelay(), 10*time.Second)

	mt = NewTimings()
	mt.Delays.Normal = 42 * time.Second
	require.EqualValues(t, mt.NormalDelay(), 42*time.Second)

}

func TestMutableTimings_BigDelay(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.BigDelay(), 30*time.Second)

	mt = NewTimings()
	mt.Delays.Big = 42 * time.Second
	require.EqualValues(t, mt.BigDelay(), 42*time.Second)

}

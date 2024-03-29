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

func TestMutableTimings_Update(t *testing.T) {

	a := NewTimings()
	a.Timeouts.Communication = 0
	a.Timeouts.Connection = 0
	a.Timeouts.Context = 0
	a.Timeouts.HostCleanup = 0
	a.Timeouts.HostCreation = 0
	a.Timeouts.HostLongOperation = 0
	a.Timeouts.HostOperation = 0
	a.Timeouts.Metadata = 0
	a.Timeouts.MetadataReadAfterWrite = 0
	a.Timeouts.Operation = 0
	a.Timeouts.HostBoot = 0
	a.Delays.Small = 0
	a.Delays.Normal = 0
	a.Delays.Big = 0
	b := NewTimings()
	b.Timeouts.Communication = 1
	b.Timeouts.Connection = 2
	b.Timeouts.Context = 3
	b.Timeouts.HostCleanup = 4
	b.Timeouts.HostCreation = 5
	b.Timeouts.HostLongOperation = 6
	b.Timeouts.HostOperation = 7
	b.Timeouts.Metadata = 8
	b.Timeouts.MetadataReadAfterWrite = 9
	b.Timeouts.Operation = 10
	b.Delays.Small = 11
	b.Delays.Normal = 12
	b.Delays.Big = 13
	b.Timeouts.HostBoot = 14

	_ = a.Update(b)

	require.EqualValues(t, a.Communication, 1)
	require.EqualValues(t, a.Connection, 2)
	require.EqualValues(t, a.Context, 3)
	require.EqualValues(t, a.HostCleanup, 4)
	require.EqualValues(t, a.HostCreation, 5)
	require.EqualValues(t, a.HostLongOperation, 6)
	require.EqualValues(t, a.HostOperation, 7)
	require.EqualValues(t, a.Metadata, 8)
	require.EqualValues(t, a.MetadataReadAfterWrite, 9)
	require.EqualValues(t, a.Operation, 10)
	require.EqualValues(t, a.Small, 11)
	require.EqualValues(t, a.Normal, 12)
	require.EqualValues(t, a.Big, 13)
	require.EqualValues(t, a.HostBoot, 14)

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

	var mt *MutableTimings
	require.EqualValues(t, mt.ContextTimeout(), 60*time.Second)

	mt = NewTimings()
	mt.Timeouts.Context = 42 * time.Second
	require.EqualValues(t, mt.ContextTimeout(), 42*time.Second)

}

func TestMutableTimings_ConnectionTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.ConnectionTimeout(), 120*time.Second)

	mt = NewTimings()
	mt.Timeouts.Connection = 42 * time.Second
	require.EqualValues(t, mt.ConnectionTimeout(), 42*time.Second)

}

func TestMutableTimings_ExecutionTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.ExecutionTimeout(), 8*time.Minute)

	mt = NewTimings()
	mt.Timeouts.Operation = 42 * time.Second
	require.EqualValues(t, mt.ExecutionTimeout(), 42*time.Second)

}

func TestMutableTimings_OperationTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.OperationTimeout(), 150*time.Second)

	mt = NewTimings()
	mt.Timeouts.Operation = 42 * time.Second
	require.EqualValues(t, mt.OperationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostCreationTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.HostCreationTimeout(), 10*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostCreation = 42 * time.Second
	require.EqualValues(t, mt.HostCreationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostCleanupTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.HostCleanupTimeout(), 5*time.Minute)

	mt = NewTimings()
	mt.Timeouts.HostCleanup = 42 * time.Second
	require.EqualValues(t, mt.HostCleanupTimeout(), 42*time.Second)

}

func TestMutableTimings_HostOperationTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.HostOperationTimeout(), 150*time.Second)

	mt = NewTimings()
	mt.Timeouts.HostOperation = 42 * time.Second
	require.EqualValues(t, mt.HostOperationTimeout(), 42*time.Second)

}

func TestMutableTimings_CommunicationTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.CommunicationTimeout(), 3*time.Minute)

	mt = NewTimings()
	mt.Timeouts.Communication = 42 * time.Second
	require.EqualValues(t, mt.CommunicationTimeout(), 42*time.Second)

}

func TestMutableTimings_HostLongOperationTimeout(t *testing.T) {

	var mt *MutableTimings
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

	var mt *MutableTimings
	require.EqualValues(t, mt.MetadataTimeout(), 150*time.Second)

	mt = NewTimings()
	mt.Timeouts.Metadata = 42 * time.Second
	require.EqualValues(t, mt.MetadataTimeout(), 42*time.Second)

}

func TestMutableTimings_MetadataReadAfterWriteTimeout(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.MetadataReadAfterWriteTimeout(), 30*time.Second)

	mt = NewTimings()
	mt.Timeouts.MetadataReadAfterWrite = 42 * time.Second
	require.EqualValues(t, mt.MetadataReadAfterWriteTimeout(), 42*time.Second)

}

func TestMutableTimings_RebootTimeout(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.RebootTimeout(), 100*time.Second)

	mt = NewTimings()
	mt.Timeouts.RebootTimeout = 42 * time.Second
	require.EqualValues(t, mt.RebootTimeout(), 42*time.Second)

}

func TestMutableTimings_SmallDelay(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.SmallDelay(), 1*time.Second)

	mt = NewTimings()
	mt.Delays.Small = 42 * time.Second
	require.EqualValues(t, mt.SmallDelay(), 42*time.Second)

}

func TestMutableTimings_NormalDelay(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.NormalDelay(), 2*time.Second)

	mt = NewTimings()
	mt.Delays.Normal = 42 * time.Second
	require.EqualValues(t, mt.NormalDelay(), 42*time.Second)

}

/*
func TestMutableTimings_DefaultDelay(t *testing.T) {

	var mt *MutableTimings = nil
	require.EqualValues(t, mt.DefaultDelay(), 10*time.Second)

	mt = NewTimings()
	mt.Delays.Normal = 42 * time.Second
	require.EqualValues(t, mt.DefaultDelay(), 42*time.Second)

}
*/

func TestMutableTimings_BigDelay(t *testing.T) {

	var mt *MutableTimings
	require.EqualValues(t, mt.BigDelay(), 5*time.Second)

	mt = NewTimings()
	mt.Delays.Big = 42 * time.Second
	require.EqualValues(t, mt.BigDelay(), 42*time.Second)

}

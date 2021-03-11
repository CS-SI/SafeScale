/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package iaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// FIXME: implement tests for caches.go
func TestBadCreateResource(t *testing.T) {
	tr, err := NewResourceCache("")
	if err == nil {
		t.FailNow()
	}
	assert.NotNil(t, err)
	assert.Nil(t, tr)
}

func TestCreateResource(t *testing.T) {
	tr, err := NewResourceCache("nuka")
	if err != nil {
		t.FailNow()
	}

	null := tr.isNull()
	if null {
		t.FailNow()
	}
}

func TestUseResource(t *testing.T) {
	tr, err := NewResourceCache("nuka")
	if err != nil {
		t.FailNow()
	}

	_ = tr
	// FIXME: Need a cacheable first
}

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

package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func doTheDefferedReengage(t *testing.T, overlord *taskGroup) {
	fu, xerr := overlord.DisarmAbortSignal()
	if xerr != nil {
		t.Errorf("Bad abort")
		t.FailNow()
	}
	defer fu()

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(goodTaskActionCitizen, nil)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	time.Sleep(12 * time.Millisecond)
	if itis, err := overlord.Abortable(); err == nil {
		if itis {
			t.Log("It is abortable and it should not!")
			t.FailNow()
		}
	} else {
		t.Log("problem checking if abortable")
		t.FailNow()
	}
}

func TestDeferredReengage(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	doTheDefferedReengage(t, overlord)

	if itis, err := overlord.Abortable(); err == nil {
		if !itis {
			t.Log("Is not abortable")
			t.FailNow()
		}
	} else {
		t.Log("Abortable cannot be checked")
		t.FailNow()
	}

	_, xerr = overlord.WaitGroup()
	require.Nil(t, xerr)
}

func TestGoodTaskActionCitizenDisengaged(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)
	_ = overlord.SetID("/taskgroup")

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fu, xerr := overlord.DisarmAbortSignal()
	require.Nil(t, xerr)
	fu()

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(goodTaskActionCitizen, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)))
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	begin := time.Now()
	time.Sleep(12 * time.Millisecond)
	if itis, err := overlord.Abortable(); err == nil {
		if itis {
			xerr = overlord.Abort()
			if xerr != nil {
				t.Errorf("Failure aborting: %v", xerr)
				t.Fail()
			}
		} else {
			t.Errorf("It should be abortable in the first place")
		}
	} else {
		t.FailNow()
	}

	end := time.Since(begin)

	time.Sleep(12 * time.Millisecond)

	_, xerr = overlord.WaitGroup()
	require.NotNil(t, xerr)

	time.Sleep(100 * time.Millisecond)

	if end >= (time.Millisecond * 300) {
		t.Errorf("It should have finished in less than 3s ms but it didn't, it was %s !!", end)
	}
}

func TestBadTaskActionCitizenDisengaged(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fu, xerr := overlord.DisarmAbortSignal()
	require.Nil(t, xerr)
	fu()
	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(badTaskActionCitizen, nil)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	begin := time.Now()
	time.Sleep(10 * time.Millisecond)
	if itis, err := overlord.Abortable(); err == nil {
		if itis {
			xerr = overlord.Abort()
			if xerr != nil {
				t.Errorf("Failure aborting: %v", xerr)
				t.Fail()
			}
		}
	} else {
		t.FailNow()
	}

	end := time.Since(begin)

	time.Sleep(60 * time.Millisecond)

	_, xerr = overlord.WaitGroup()
	require.NotNil(t, xerr)

	time.Sleep(100 * time.Millisecond)

	if end >= (time.Millisecond * 300) {
		t.Errorf("It should have finished in less than 3s ms but it didn't, it was %s !!", end)
	}
}

func TestAwfulTaskActionCitizenDisengaged(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fu, xerr := overlord.DisarmAbortSignal()
	require.Nil(t, xerr)
	fu()
	fmt.Println("Begin")

	stCh := make(chan string, 100)

	numChild := 4 // No need to push it
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(horribleTaskActionCitizen, stCh)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	time.Sleep(10 * time.Millisecond)
	if itis, err := overlord.Abortable(); err == nil {
		if itis {
			xerr = overlord.Abort()
			if xerr != nil {
				t.Errorf("Failure aborting: %v", xerr)
				t.Fail()
			}
		}
	} else {
		t.FailNow()
	}

	time.Sleep(60 * time.Millisecond)

	// task cannot be aborted, subtasks never return, a WaitGroup here would wait forever
	ended, _, xerr := overlord.WaitGroupFor(2 * time.Second)
	if xerr == nil { // It should fail because it's an aborted task...
		t.FailNow()
	}
	if ended { // it didn't, it is a timeout
		t.FailNow()
	}

	time.Sleep(500 * time.Millisecond)

	_ = w.Close()

	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout
	_ = out

	count := len(stCh)
	if count < 5 {
		t.Fail()
	}
}

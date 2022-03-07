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

package serialize

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// LikeFeatures ...
type LikeFeatures struct {
	Installed   map[string]string   `json:"installed"`
	Disabled    map[string]struct{} `json:"disabled"`
	TakeControl string
}

func newLikeFeatures() *LikeFeatures {
	return &LikeFeatures{
		Installed: map[string]string{},
		Disabled:  map[string]struct{}{},
	}
}

// Content ...
// satisfies interface data.Clonable
func (f *LikeFeatures) IsNull() bool {
	return f == nil || (len(f.Installed) == 0 && len(f.Disabled) == 0)
}

func (f LikeFeatures) Clone() (data.Clonable, error) {
	return newLikeFeatures().Replace(&f)
}

func (f *LikeFeatures) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if f == nil || p == nil {
		return f, nil
	}

	src, ok := p.(*LikeFeatures)
	if !ok {
		return nil, fmt.Errorf("p is not a *LikeFeatures")
	}
	f.Installed = make(map[string]string, len(src.Installed))
	for k, v := range src.Installed {
		f.Installed[k] = v
	}
	f.Disabled = make(map[string]struct{}, len(src.Installed))
	for k, v := range src.Disabled {
		f.Disabled[k] = v
	}
	return f, nil
}

func TestJsonProperty_IsNull(t *testing.T) {

	var jp *jsonProperty = nil
	result := jp.IsNull()
	require.EqualValues(t, result, true)

}

func TestJsonProperty_Replace(t *testing.T) {

	var jp *jsonProperty = nil
	var data data.Clonable = nil

	result, _ := jp.Replace(data)
	require.EqualValues(t, fmt.Sprintf("%p", result), "0x0")
	require.EqualValues(t, fmt.Sprintf("%p", jp), "0x0")

}

func TestNewJSONProperties(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)
}

func TestLockForReadDoesNotChange(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")

	assert.NotNil(t, clusters)

	err := clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, err)

	textDump := spew.Sdump(clusters)
	assert.False(t, strings.Contains(textDump, "Ipsum"))
}

func TestLockForWriteDoesChange(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	err := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, err)

	textDump := spew.Sdump(clusters)
	assert.True(t, strings.Contains(textDump, "Ipsum"))
}

func TestLockForReadDoesLock(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	xerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good

	// Let's test sync

	// this goroutine first sleeps, then gets the lock and prints something, the sleep ensures that the routine should be
	// the second routine getting the lock
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1500 * time.Millisecond)
		oerr := clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("second there")
			defer fmt.Println("end second there")
			thing := clonable.(*LikeFeatures)
			trump := thing.Installed["Loren"]
			fmt.Printf("Watch, in goroutine: %s", trump)
			return nil
		})
		assert.Nil(t, oerr)
	}()

	// That should have the lock first, the sleep in inside the lock
	_ = clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
		fmt.Println("first there")
		defer fmt.Println("end first there")
		time.Sleep(3 * time.Second)
		thing := clonable.(*LikeFeatures)
		gotcha := thing.Installed["Loren"]
		fmt.Println(gotcha)
		return nil
	})

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)
	if strings.Contains(outString, "IpsumIpsum") {
		t.Fail()
	}
	fmt.Println(outString)
}

func TestWriteDeterministicLocks(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	xerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good

	// Let's test sync

	// this goroutine first sleeps, then gets the lock and prints something, the sleep ensures that the routine should be
	// the second routine getting the lock
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(150 * time.Millisecond)
		oerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Writer")
			defer fmt.Println("End Writer")
			thing := clonable.(*LikeFeatures)
			fmt.Println("Writing content")
			thing.Installed["Loren"] = "Dolor sit"
			time.Sleep(800 * time.Millisecond)
			return nil
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		oerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Writer 2")
			defer fmt.Println("End Writer 2")
			thing := clonable.(*LikeFeatures)
			time.Sleep(800 * time.Millisecond)
			thing.Installed["Loren"] = "amet"
			return nil
		})
		assert.Nil(t, oerr)
	}()

	// That should have the lock first, the sleep in inside the lock
	time.Sleep(80 * time.Millisecond)
	_ = clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
		fmt.Println("Reader")
		defer fmt.Println("End Reader")
		thing := clonable.(*LikeFeatures)
		gotcha := thing.Installed["Loren"]
		fmt.Printf("Rising tide: %s\n", gotcha)
		return nil
	})

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)
	if strings.Contains(outString, "IpsumIpsum") {
		t.Fail()
	}
	fmt.Println(outString)
}

func TestEternalReaderLocks(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	xerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good

	// Let's test sync

	// this goroutine first sleeps, then gets the lock and prints something, the sleep ensures that the routine should be
	// the second routine getting the lock
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(200 * time.Millisecond)
		oerr := clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Slow Reader")
			defer fmt.Println("End slow Reader")
			time.Sleep(500 * time.Millisecond)
			thing := clonable.(*LikeFeatures)
			fmt.Printf("Recovering content: %s", thing.Installed["Loren"])
			return nil
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(500 * time.Millisecond)
		oerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Writer 2")
			defer fmt.Println("End Writer 2")
			thing := clonable.(*LikeFeatures)
			thing.Installed["Loren"] = "amet"
			return nil
		})
		assert.Nil(t, oerr)
	}()

	// That should have the lock first, the sleep in inside the lock
	time.Sleep(800 * time.Millisecond)
	_ = clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
		fmt.Println("Reader")
		defer fmt.Println("End Reader")
		thing := clonable.(*LikeFeatures)
		gotcha := thing.Installed["Loren"]
		fmt.Printf("Rising tide: %s\n", gotcha)
		return nil
	})

	failed := waitTimeout(&wg, 3*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)
	if strings.Contains(outString, "IpsumIpsum") {
		t.Fail()
	}
	fmt.Println(outString)
}

func TestLockAndWriteLocks(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	xerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good

	// Let's test sync

	// this goroutine first sleeps, then gets the lock and prints something, the sleep ensures that the routine should be
	// the second routine getting the lock
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(150 * time.Millisecond)
		oerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Writer")
			defer fmt.Println("End Writer")
			thing := clonable.(*LikeFeatures)
			fmt.Println("Writing content")
			thing.Installed["Loren"] = "Dolor sit"
			time.Sleep(800 * time.Millisecond)
			return nil
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		oerr := clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
			fmt.Println("Reader 2")
			defer fmt.Println("End Reader 2")
			thing := clonable.(*LikeFeatures)
			gotcha := thing.Installed["Loren"]
			fmt.Println(gotcha)
			return nil
		})
		assert.Nil(t, oerr)
	}()

	// That should have the lock first, the sleep in inside the lock
	time.Sleep(300 * time.Millisecond)
	_ = clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
		fmt.Println("Reader")
		defer fmt.Println("End Reader")
		thing := clonable.(*LikeFeatures)
		gotcha := thing.Installed["Loren"]
		fmt.Println(gotcha)
		return nil
	})

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	outString := string(out)
	if strings.Contains(outString, "IpsumIpsum") {
		t.Fail()
	}
	fmt.Println(outString)
}

// WaitGroup with timeout, returns true when it's a timeout
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c: // OK
		return false
	case <-time.After(timeout): // timeout
		return true
	}
}

func TestNestedLocks(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	xerr := clusters.Alter("first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good
	// one at a time ??

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		xerr = clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got first lock")
			time.Sleep(500 * time.Millisecond)
			return clusters.Inspect("second", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks here")
				return nil
			})
		})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		oerr := clusters.Inspect("second", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got second lock")
			time.Sleep(500 * time.Millisecond)
			return clusters.Inspect("first", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}

	assert.Nil(t, xerr)
}

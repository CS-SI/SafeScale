package serialize

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

// Lorem ipsum dolor sit amet, consectetur adipiscing elit. In et nulla eros. Ut pharetra, arcu at bibendum ullamcorper, leo magna condimentum leo, at rhoncus dui turpis vel ante. Curabitur ac leo vel massa pretium maximus. In sed gravida felis. Etiam lacinia, sem at sollicitudin tempus, tortor dolor porta leo, ut suscipit ex mi eget eros. Praesent id ultricies metus. Morbi condimentum placerat elementum. Morbi et sem ligula.

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
func (f *LikeFeatures) Content() data.Clonable {
	return f
}

func (f *LikeFeatures) Clone() data.Clonable {
	return newLikeFeatures().Replace(f)
}

func (f *LikeFeatures) Replace(p data.Clonable) data.Clonable {
	src := p.(*LikeFeatures)
	f.Installed = make(map[string]string, len(src.Installed))
	for k, v := range src.Installed {
		f.Installed[k] = v
	}
	f.Disabled = make(map[string]struct{}, len(src.Installed))
	for k, v := range src.Disabled {
		f.Disabled[k] = v
	}
	return f
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
	task, _ := concurrency.NewUnbreakableTask()

	assert.NotNil(t, clusters)

	err := clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	err := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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
	_ = clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
	_ = clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
	_ = clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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
	_ = clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

func TestNestedLocksWithWritesDanger(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got first lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "second", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks here")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		oerr := clusters.Alter(task, "second", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got second lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
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
		xerr = clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got first lock")
			time.Sleep(500 * time.Millisecond)
			return clusters.Inspect(task, "second", func(clonable data.Clonable) fail.Error {
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
		oerr := clusters.Inspect(task, "second", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got second lock")
			time.Sleep(500 * time.Millisecond)
			return clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
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

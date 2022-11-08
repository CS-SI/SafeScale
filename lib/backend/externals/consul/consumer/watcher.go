package consumer

import (
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/sirupsen/logrus"
)

type watcher struct {
	*watch.Plan
	lock          *sync.RWMutex
	lastKVPairs   map[string]*consulapi.KVPair
	hybridHandler watch.HybridHandlerFunc
	stopCh        chan struct{}
	errCh         chan error
}

func newWatcher(path string) (*watcher, fail.Error) {
	plan, err := watch.Parse(map[string]any{"type": "keyprefix", "prefix": path})
	if err != nil {
		return nil, fail.Wrap(err)
	}

	out := &watcher{
		Plan:        plan,
		lastKVPairs: make(map[string]*consulapi.KVPair),
		errCh:       make(chan error, 1),
		lock:        &sync.RWMutex{},
	}
	return out, nil
}

func (w *watcher) lastKVPair(path string) *consulapi.KVPair {
	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.lastKVPairs[path]
}

func (w *watcher) updateValue(path string, value *consulapi.KVPair) {
	w.lock.Lock()
	defer w.lock.Unlock()

	if value == nil {
		delete(w.lastKVPairs, path)
	} else {
		w.lastKVPairs[path] = value
	}
}

func (w *watcher) setHybridHandler(prefix string, handler func(*consulapi.KVPair)) {
	w.lock.Lock()
	defer w.lock.Unlock()

	w.hybridHandler = func(bp watch.BlockingParamVal, data any) {
		kvPairs, err := lang.Cast[consulapi.KVPairs](data)
		if err != nil {
			logrus.Errorf("in watcher.hybridHandler call: %v", err)
		}

		for _, v := range kvPairs {
			path := strings.TrimSuffix(strings.TrimPrefix(v.Key, prefix+"/"), "/")
			prev := w.lastKVPair(path)

			if prev.ModifyIndex == v.ModifyIndex {
				continue
			}

			w.updateValue(path, v)
			handler(v)
		}
	}
}

func (w *watcher) run(conf *consulapi.Config) fail.Error {
	w.lock.Lock()
	w.stopCh = make(chan struct{})
	w.Plan.HybridHandler = w.hybridHandler
	w.lock.Unlock()

	go func() {
		w.errCh <- w.RunWithConfig(conf.Address, conf)
	}()

	select {
	case err := <-w.errCh:
		return fail.Wrap(err, "watcher run fail")
	case <-w.stopCh:
		w.Stop()
		return nil
	}
}

func (w *watcher) stop() {
	close(w.stopCh)
}

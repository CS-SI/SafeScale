//go:build disabled
// +build disabled

//FIXME: need to move NewServiceTest inside a package

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

package operations

import (
	"context"
	"crypto/md5" // nolint
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/eko/gocache/v2/cache"

	// "github.com/CS-SI/SafeScale/v22/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
)

var SHORTEN_TIMINGS = &temporal.MutableTimings{
	Timeouts: temporal.Timeouts{
		Communication:          100 * time.Millisecond,
		Connection:             100 * time.Millisecond,
		Context:                100 * time.Millisecond,
		HostCreation:           4 * time.Second, // 100ms too fast for concurrency, makes break clustertasks
		HostCleanup:            100 * time.Millisecond,
		HostOperation:          100 * time.Millisecond,
		HostLongOperation:      100 * time.Millisecond,
		Operation:              100 * time.Millisecond,
		Metadata:               100 * time.Millisecond,
		MetadataReadAfterWrite: 100 * time.Millisecond,
		SSHConnection:          100 * time.Millisecond,
		RebootTimeout:          100 * time.Millisecond,
	},
	Delays: temporal.Delays{
		Small:  100 * time.Millisecond,
		Normal: 100 * time.Millisecond,
		Big:    100 * time.Millisecond,
	},
}

type ServiceTest struct {
	iaas.Service
	internals ServiceTestInternals
	memory    ServiceTestMemory
	options   ServiceTestOptions
}

type ServiceTestBucketData struct {
	data map[string]string
	mu   sync.Mutex
}

type ServiceTestCacheData struct {
	// data map[string]cache.Store
	data map[string]interface{}
	mu   sync.Mutex
}

type ServiceTestFsData struct {
	data map[string][]byte
	mu   sync.Mutex
}

type ServiceTestInternals struct {
	t          *testing.T
	tmpdir     string                // Temporary directory
	bucketData ServiceTestBucketData // Contains bucket data (emulated local)
	cache      ServiceTestCacheData  // Contains cache data (emulated local)
	fsCache    ServiceTestFsData     // Contains file data (emulated local)
	loglevel   uint                  // 0: none, 1: no data details, 2: full data vision
}
type ServiceTestMemory struct {
	keypairs map[string]*abstract.KeyPair
}

type ServiceTestOptions struct {
	candisablesecuritygroup bool                         // Set GetCapabilities().CanDisableSecurityGroup
	enablecache             bool                         // Enable use cache
	metadatakey             string                       // Response of .GetMetaData(). Used to cypher bucket data,
	metadatakeyErr          fail.Error                   // Error of .GetMetaData()
	timings                 *temporal.MutableTimings     // Response of .Timings()
	timingsErr              fail.Error                   // Error of .Timings()
	metadatabucket          abstract.ObjectStorageBucket // Response of .GetMetadataBucket()
	metadatabucketErr       fail.Error                   // Error of .GetMetadataBucket()
	listobjectsErr          fail.Error                   // Error of .ListObjects()
	version                 string                       // Response of .Read(version)
	versionErr              fail.Error                   // Error of .Read(version)
	name                    string                       // Response of .GetName()
	nameErr                 fail.Error                   // Error  of .GetName()
	operatorusername        string                       //
	operatorusernameErr     fail.Error                   //
	providername            string                       // Response of .GetProviderName()
	providernameErr         fail.Error                   // Error of .GetProviderName()
	stackname               string                       // Response of .GetStackName()
	stacknameErr            fail.Error                   // Error of .GetStackName()
	defaultsgname           string                       // Response of .GetDefaultSecurityGroupName()
	defaultsgnameErr        fail.Error                   // Error of .GetDefaultSecurityGroupName()
	onsshcommand            func(string) string          // Emulated SSH command response
	protocol                string                       // Response of .Protocol()
	protocolErr             fail.Error                   // Error of .Protocol()
}

type ServiceOptionSetMap struct {
	strtype string
	setter  func(svc *ServiceTest, v interface{}) string
}

var ServiveOptionsSetMap = map[string]ServiceOptionSetMap{
	"candisablesecuritygroup": {
		strtype: "bool",
		setter: func(svc *ServiceTest, v interface{}) string {
			if b, ok := v.(bool); ok {
				svc.options.candisablesecuritygroup = b
				if b {
					return "bool(true)"
				} else {
					return "bool(false)"
				}
			}
			return ""
		},
	},
	"enablecache": {
		strtype: "bool",
		setter: func(svc *ServiceTest, v interface{}) string {
			if b, ok := v.(bool); ok {
				svc.options.enablecache = b
				if b {
					return "bool(true)"
				} else {
					return "bool(false)"
				}
			}
			return ""
		},
	},
	"timings": {
		strtype: "*temporal.MutableTimings",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(*temporal.MutableTimings); ok {
				svc.options.timings = v
				return "*temporal.MutableTimings{}"
			}
			return ""
		},
	},
	"timingsErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.timingsErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"metadatakey": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.metadatakey = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"metadatakeyErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.metadatakeyErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"metadatabucket": {
		strtype: "abstract.ObjectStorageBucket",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(abstract.ObjectStorageBucket); ok {
				svc.options.metadatabucket = v
				return "ObjectStorageBucket{}"
			}
			return ""
		},
	},
	"metadatabucketErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.metadatabucketErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"listobjectsErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.listobjectsErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"version": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.version = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"versionErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.versionErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())

			}
			return ""
		},
	},
	"name": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.name = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"nameErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.nameErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"providername": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.providername = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"providernameErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.providernameErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"stackname": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.stackname = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"stacknameErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.stacknameErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"defaultsgname": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.defaultsgname = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"defaultsgnameErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.defaultsgnameErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"protocol": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.protocol = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"protocolErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.protocolErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
	"onsshcommand": {
		strtype: "func(string) string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(func(string) string); ok {
				svc.options.onsshcommand = v
				return "func(string) string"
			}
			return ""
		},
	},
	"operatorusername": {
		strtype: "string",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(string); ok {
				svc.options.operatorusername = v
				return fmt.Sprintf("string(%s)", v)
			}
			return ""
		},
	},
	"operatorusernameErr": {
		strtype: "fail.Error",
		setter: func(svc *ServiceTest, v interface{}) string {
			if v, ok := v.(fail.Error); ok {
				svc.options.operatorusernameErr = v
				return fmt.Sprintf("fail.Error(%s)", v.Error())
			}
			return ""
		},
	},
}

func NewServiceTest(t *testing.T, routine func(svc *ServiceTest)) error {

	dir, err := ioutil.TempDir("", "safescale_NewServiceTest")
	if err != nil {
		return err
	}

	svc := &ServiceTest{
		internals: ServiceTestInternals{
			t:      t,
			tmpdir: dir,
			bucketData: ServiceTestBucketData{
				data: make(map[string]string),
				mu:   sync.Mutex{},
			},
			cache: ServiceTestCacheData{
				// data: make(map[string]cache.Store),
				data: make(map[string]interface{}),
				mu:   sync.Mutex{},
			},
			fsCache: ServiceTestFsData{
				data: make(map[string][]byte),
				mu:   sync.Mutex{},
			},
			loglevel: 2,
		},
		memory: ServiceTestMemory{
			keypairs: make(map[string]*abstract.KeyPair),
		},
		options: ServiceTestOptions{},
	}
	svc._reset()

	xerr := svc._shortenTimings(func() fail.Error {
		SSHConnectorTest_Overload(svc, routine)
		return nil
	})
	_ = os.RemoveAll(dir)
	return xerr
}

/*** Special methods for tests ***/
func (e *ServiceTest) _reset() {
	e._log("ServiceTest::_reset")

	e.internals.bucketData.mu.Lock()
	e.internals.bucketData.data = make(map[string]string) // Empty bucket data
	e.internals.bucketData.mu.Unlock()

	e.internals.cache.mu.Lock()
	// e.internals.cache.data = make(map[string]cache.Store)
	e.internals.cache.data = make(map[string]interface{})
	e.internals.cache.mu.Unlock()

	e.internals.fsCache.mu.Lock()
	e.internals.fsCache.data = make(map[string][]byte)
	e.internals.fsCache.mu.Unlock()

	e.options.candisablesecuritygroup = true
	e.options.enablecache = false
	e.options.timings = temporal.NewTimings()
	e.options.timingsErr = nil
	e.options.metadatakey = "my-secret"
	e.options.metadatakeyErr = nil
	e.options.metadatabucket = abstract.ObjectStorageBucket{
		ID:         "ServiceTestBucket",
		Name:       "ServiceTestBucket",
		Host:       "localhost",
		MountPoint: e.internals.tmpdir,
	}
	e.options.metadatabucketErr = nil
	e.options.listobjectsErr = nil
	e.options.version = MinimumMetadataVersion
	e.options.versionErr = nil
	e.options.name = "MyServiceTest"
	e.options.nameErr = nil
	e.options.operatorusername = "safescale"
	e.options.operatorusernameErr = nil
	e.options.providername = "MyServiceTest-provider"
	e.options.providernameErr = nil
	e.options.stackname = "MyServiceTest-Stack"
	e.options.stacknameErr = nil
	e.options.defaultsgname = "MyServiceTest-SecurityGroup"
	e.options.defaultsgnameErr = nil
	e.options.onsshcommand = func(string) string {
		return ""
	}
	e.options.protocol = "rclone-s3.conf"
	e.options.protocolErr = nil

	e.memory.keypairs = make(map[string]*abstract.KeyPair)
}
func (e *ServiceTest) _setLogLevel(level uint) {
	e.internals.loglevel = 2
	e._logf("ServiceTest::_setLogLevel { value: %d }", level)
	e.internals.loglevel = level
	if e.internals.loglevel > 2 {
		e.internals.loglevel = 2
	}
}
func (e *ServiceTest) _sshCommand(in string) string {

	if len(in) > 16 && in[0:16] == "/usr/bin/md5sum " {
		hash, xerr := e._getFsCacheMD5(in[16:])
		if xerr == nil {
			return fmt.Sprintf("echo \"%s\"", hash)
		}
	}

	return e.options.onsshcommand(in)
}
func (e *ServiceTest) _updateOption(name string, value interface{}) {
	v, ok := ServiveOptionsSetMap[name]
	if !ok {
		e._logf("ServiceTest::_updateOption error, option \"%s\" not found", name)
	} else {
		stringified := v.setter(e, value)
		if stringified == "" {
			e._logf("ServiceTest::_updateOption error, fail to cast given option \"%s\" to \"%s\"", name, v.strtype)
		} else {
			e._logf("ServiceTest::_updateOption { name: \"%s\", value: %s}", name, stringified)
		}
	}
}

func (e *ServiceTest) _getRawInternalData(path string) (string, error) {

	e.internals.bucketData.mu.Lock()
	serial, ok := e.internals.bucketData.data[path]
	e.internals.bucketData.mu.Unlock()

	if !ok {
		return "", errors.New(fmt.Sprintf("Key \"%s\" not found", path)) // nolint
	}
	return serial, nil
}
func (e *ServiceTest) _getInternalData(path string) (string, error) {
	key, err := crypt.NewEncryptionKey([]byte(e.options.metadatakey))
	if err != nil {
		return "", err
	}
	e.internals.bucketData.mu.Lock()
	serial, ok := e.internals.bucketData.data[path]
	e.internals.bucketData.mu.Unlock()
	if !ok {
		return "", errors.New(fmt.Sprintf("Key \"%s\" not found", path)) // nolint
	}
	bytes, xerr := crypt.Decrypt([]byte(serial), key)
	if xerr != nil {
		return "", xerr
	}
	return string(bytes), nil
}
func (e *ServiceTest) _getInternalDataKeys(prefix string) []string {
	keys := make([]string, 0)
	e.internals.bucketData.mu.Lock()
	for k := range e.internals.bucketData.data {
		if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			keys = append(keys, k)
		}
	}
	e.internals.bucketData.mu.Unlock()
	return keys
}
func (e *ServiceTest) _setInternalData(path string, v interface{}) error {
	serial, err := e._encodeItem(v)
	if err != nil {
		return err
	}

	// Chunk fields
	obj, _ := v.(interface{ Serialize() ([]byte, fail.Error) })
	dataValue := "[Serial]"
	if e.internals.loglevel > 1 {
		d, _ := obj.Serialize()
		dataValue = string(d)
	}

	e._logf("ServiceTest::_setInternalData { path: \"%s\", value: %s }", path, dataValue)
	e.internals.bucketData.mu.Lock()
	e.internals.bucketData.data[path] = serial
	e.internals.bucketData.mu.Unlock()
	return nil
}
func (e *ServiceTest) _hasInternalData(path string) bool {
	e.internals.bucketData.mu.Lock()
	_, ok := e.internals.bucketData.data[path]
	e.internals.bucketData.mu.Unlock()
	return ok
}
func (e *ServiceTest) _deleteInternalData(path string) error {
	e._logf("ServiceTest::_deleteInternalData { path: \"%s\" }", path)
	e.internals.bucketData.mu.Lock()
	_, ok := e.internals.bucketData.data[path]
	e.internals.bucketData.mu.Unlock()
	if !ok {
		return errors.New(fmt.Sprintf("Key \"%s\" not found", path)) // nolint
	}
	e.internals.bucketData.mu.Lock()
	delete(e.internals.bucketData.data, path)
	e.internals.bucketData.mu.Unlock()
	return nil
}
func (e *ServiceTest) _encodeItem(v interface{}) (string, error) {
	key, err := crypt.NewEncryptionKey([]byte(e.options.metadatakey))
	if err != nil {
		return "", err
	}
	obj, ok := v.(interface{ Serialize() ([]byte, fail.Error) })
	if !ok {
		e._logf("ServiceTest::encodeItem error, item \"%s\" value require being Serializable", reflect.TypeOf(v).String())
		return "", errors.New("require has Serialize method")
	}
	serial, err := obj.Serialize()
	if err != nil {
		return "", err
	}
	encoded, xerr := crypt.Encrypt(serial, key)
	if xerr != nil {
		return "", xerr
	}
	return string(encoded), nil
}
func (e *ServiceTest) _decodeItem(serial string) (string, error) {
	key, err := crypt.NewEncryptionKey([]byte(e.options.metadatakey))
	if err != nil {
		return "", err
	}
	decoded, xerr := crypt.Decrypt([]byte(serial), key)
	if xerr != nil {
		return "", xerr
	}
	return string(decoded), nil
}

func (e *ServiceTest) _getFsCache(path string) ([]byte, fail.Error) {
	e._logf("ServiceTest::_getFsCache {path: \"%s\"} ", path)
	e.internals.fsCache.mu.Lock()
	b, ok := e.internals.fsCache.data[path]
	e.internals.fsCache.mu.Unlock()
	if !ok {
		return []byte{}, fail.NotFoundError(fmt.Sprintf("fscache \"%s\"not found", path))
	}
	return b, nil
}
func (e *ServiceTest) _getFsCacheMD5(path string) (string, fail.Error) {
	e.internals.fsCache.mu.Lock()
	b, ok := e.internals.fsCache.data[path]
	e.internals.fsCache.mu.Unlock()
	if !ok {
		e._errorf("ServiceTest::_getFsCacheMD5 {path: \"%s\"} not found ", path)
		return "", fail.NotFoundError(fmt.Sprintf("fscache \"%s\"not found", path))
	}
	hasher := md5.New() // nolint
	_, err := hasher.Write(b)
	if err != nil {
		e._errorf("ServiceTest::_getFsCacheMD5 {path: \"%s\"} not hashable", path)
		return "", fail.Wrap(err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	e._logf("ServiceTest::_getFsCacheMD5 {path: \"%s\", hash: \"%s\"} ", path, hash)
	return hash, nil
}
func (e *ServiceTest) _setFsCache(path string, data []byte) fail.Error {
	if e.internals.loglevel == 2 {
		e._logf("ServiceTest::_setFsCache {path: \"%s\", data: \"%s\"} ", path, string(data))
	} else {
		e._logf("ServiceTest::_setFsCache {path: \"%s\", data: \"bytes(%d)\"} ", path, len(string(data)))
	}

	if path == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("path")
	}
	e.internals.fsCache.mu.Lock()
	e.internals.fsCache.data[path] = data
	e.internals.fsCache.mu.Unlock()
	return nil
}
func (e *ServiceTest) _shortenTimings(routine func() fail.Error) (ferr fail.Error) {

	defer func() {
		r := recover()
		if r != nil {
			msg := ""
			if anError, ok := r.(error); ok {
				msg = anError.Error()
			} else {
				msg = r.(string)
			}
			// FIXME: Due from timeout shortcuts, but strange behaviour, should check for deadlocks
			if strings.Contains(msg, "race detected during execution of test") {
				e.internals.t.Log("race detected during execution of test")
				e.internals.t.Skip()
			} else {
				ferr = fail.NewError(msg)
			}
		}
	}()

	err := e.options.timings.Update(SHORTEN_TIMINGS)
	if err != nil {
		ferr = fail.Wrap(err)
	} else {
		ferr = routine()
	}
	defer func() {
		err = e.options.timings.Update(temporal.NewTimings())
		if err != nil {
			ferr = fail.Wrap(err)
		}
	}()
	return ferr
}

func (e *ServiceTest) _cramp(msg string, length int) string { // nolint
	output := msg
	if len(output) > length {
		output = output[0:length]
	}
	return output
}
func (e *ServiceTest) _tracef(color string, msg string, args ...interface{}) {
	if e.internals.loglevel > 0 {
		txt := fmt.Sprintf("\033[%sm%s\033[0m", color, msg)
		if len(args) == 0 {
			e.internals.t.Log(txt) // nodebug
		} else {
			e.internals.t.Logf(txt, args...) // nodebug
		}
	}
}
func (e *ServiceTest) _log(msg string) {
	e._tracef("0", msg)
}
func (e *ServiceTest) _logf(msg string, args ...interface{}) {
	e._tracef("0", msg, args...)
}
func (e *ServiceTest) _warn(msg string) {
	e._tracef("33", msg)
}
func (e *ServiceTest) _warnf(msg string, args ...interface{}) {
	e._tracef("33", msg, args...)
}
func (e *ServiceTest) _error(msg string) {
	e._tracef("31", msg)
}
func (e *ServiceTest) _errorf(msg string, args ...interface{}) {
	e._tracef("31", msg, args...)
}
func (e *ServiceTest) _survey(msg string) {
	e._tracef("34", msg)
}
func (e *ServiceTest) _surveyf(msg string, args ...interface{}) {
	e._tracef("34", msg, args...)
}

/*****/

func (e *ServiceTest) FilterImages(ctx context.Context, name string) ([]*abstract.Image, fail.Error) {
	e._surveyf("ServiceTest::FilterImages { name: \"%s\" } (not implemented)", name)
	return make([]*abstract.Image, 0), nil
}
func (e *ServiceTest) FindTemplateBySizing(ctx context.Context, hsr abstract.HostSizingRequirements) (*abstract.HostTemplate, fail.Error) {
	e._logf("ServiceTest::FindTemplateBySizing { Cores: %d, RAMSize: %f, DiskSize: %d, GPUNumber: %d, CPUFreq: %f }", hsr.MinCores, hsr.MinRAMSize, hsr.MinDiskSize, hsr.MinGPU, hsr.MinCPUFreq)

	// Auto generate template
	return &abstract.HostTemplate{
		Cores:     hsr.MinCores,
		RAMSize:   hsr.MinRAMSize,
		DiskSize:  hsr.MinDiskSize,
		GPUNumber: hsr.MinGPU,
		GPUType:   "",
		CPUFreq:   hsr.MinCPUFreq,
		ID:        "ServiceTest-SelfGenerated-Template",
		Name:      "ServiceTest-SelfGenerated-Template",
	}, nil

}
func (e *ServiceTest) FindTemplateByName(ctx context.Context, name string) (*abstract.HostTemplate, fail.Error) {
	e._surveyf("ServiceTest::FindTemplateByName { name: \"%s\" } (not implemented)", name)
	return nil, nil
}
func (e *ServiceTest) GetProviderName() (string, fail.Error) {
	if e.options.providernameErr != nil {
		e._warnf("ServiceTest::GetProviderName forced error \"%s\"", e.options.providernameErr.Error())
		return "", e.options.providernameErr
	}
	return e.options.providername, nil
}
func (e *ServiceTest) GetMetadataBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error) {
	if e.options.metadatabucketErr != nil {
		e._warnf("ServiceTest::GetMetadataBucket forced error \"%s\"", e.options.metadatabucketErr.Error())
		return abstract.ObjectStorageBucket{}, e.options.metadatabucketErr
	}
	return e.options.metadatabucket, nil
}

func (e *ServiceTest) ListHostsByName(ctx context.Context, value bool) (map[string]*abstract.HostFull, fail.Error) {
	e._survey("ServiceTest::ListHostsByName (not implemented)")
	return map[string]*abstract.HostFull{}, nil
}
func (e *ServiceTest) ListTemplatesBySizing(context.Context, abstract.HostSizingRequirements, bool) ([]*abstract.HostTemplate, fail.Error) {
	e._survey("ServiceTest::ListTemplatesBySizing (not implemented)")
	return []*abstract.HostTemplate{}, nil
}
func (e *ServiceTest) ObjectStorageConfiguration(ctx context.Context) (objectstorage.Config, fail.Error) {
	e._survey("ServiceTest::ObjectStorageConfiguration (not implemented)")
	return objectstorage.Config{}, nil
}
func (e *ServiceTest) SearchImage(ctx context.Context, ref string) (*abstract.Image, fail.Error) {
	e._logf("ServiceTest::SearchImage { ref: \"%s\" } (auto generate)", ref)
	if ref == "" {
		return nil, fail.NotFoundError("Image not found")
	}
	img := &abstract.Image{
		ID:          ref,
		Name:        ref,
		URL:         "Image URL",
		Description: "Image Description",
		StorageType: "Image Storage Type",
		DiskSize:    64,
	}
	return img, nil
}
func (e *ServiceTest) TenantCleanup(context.Context, bool) fail.Error {
	e._survey("ServiceTest::TenantCleanup (not implemented)")
	return nil
}
func (e *ServiceTest) WaitHostState(ctx context.Context, name string, state hoststate.Enum, timeout time.Duration) fail.Error {

	e._surveyf("ServiceTest::WaitHostState { name: \"%s\", state: \"%s\" } (emulated)", name, state.String())

	host, xerr := LoadHost(ctx, e, name)
	if xerr != nil {
		return xerr
	}

	xerr = host.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		ahc.LastState = state
		return nil
	})

	return nil // fail.TimeoutError(errors.New("timeout"), timeout, "host has not start in time")
}
func (e *ServiceTest) WaitVolumeState(context.Context, string, volumestate.Enum, time.Duration) (*abstract.Volume, fail.Error) {
	e._survey("ServiceTest::WaitVolumeState (not implemented)")
	return nil, nil
}

func (e *ServiceTest) GetCache(ctx context.Context) (cache.CacheInterface, fail.Error) {
	e._surveyf("ServiceTest::GetCache { name: \"%s\", enabled: %t } (DEPRECATED)", "none", e.options.enablecache)
	/*
		if name == "" {
			return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
		}
		if e.options.enablecache {
			return NewCacheTest(name, e), nil
		}
		var c cache.Cache = NewCacheTest("name", e)
	*/
	// return nil, fail.NotAvailableError("No cache available !")
	return nil, nil
}

/*
func (e *ServiceTest) _cache_Get(ctx context.Context, cachename string, key string, options ...data.ImmutableKeyValue) (ce *cache.Entry, xerr fail.Error) { // nolint
	e._surveyf("ServiceTest::_cache_Get { cache: \"%s\", key: \"%s\" } (not implemented)", cachename, key)

	e.internals.cache.mu.Lock()
	store, ok := e.internals.cache.data[cachename]
	e.internals.cache.mu.Unlock()
	if !ok {
		store, xerr = cache.NewMapStore(cachename)
		if xerr != nil {
			return nil, xerr
		}
		e.internals.cache.mu.Lock()
		e.internals.cache.data[cachename] = store
		e.internals.cache.mu.Unlock()
	}
	e.internals.cache.mu.Unlock()
	return store.Entry(ctx, key)
}
func (e *ServiceTest) _cache_ReserveEntry(ctx context.Context, cachename string, key string, timeout time.Duration) fail.Error {
	e._surveyf("ServiceTest::_cache_ReserveEntry { cache: \"%s\", key: \"%s\" }(not implemented)", cachename, key)
	e.internals.cache.mu.Lock()
	store, ok := e.internals.cache.data[cachename]
	e.internals.cache.mu.Unlock()
	if !ok {
		return fail.NotFoundError("Cache \"%s\" not found", cachename)
	}
	return store.Reserve(ctx, key, timeout)
}
func (e *ServiceTest) _cache_CommitEntry(ctx context.Context, cachename string, key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	e._surveyf("ServiceTest::_cache_CommitEntry { cache: \"%s\", key: \"%s\", content: \"%s\" } (not implemented)", cachename, key, reflect.TypeOf(content).String())
	e.internals.cache.mu.Lock()
	store, ok := e.internals.cache.data[cachename]
	e.internals.cache.mu.Unlock()
	if !ok {
		return nil, fail.NotFoundError("Cache \"%s\" not found", cachename)
	}
	return store.Commit(ctx, key, content)
}
func (e *ServiceTest) _cache_FreeEntry(ctx context.Context, cachename string, key string) fail.Error {
	e._surveyf("ServiceTest::_cache_FreeEntry { cache: \"%s\", key: \"%s\" } (not implemented)", cachename, key)
	e.internals.cache.mu.Lock()
	store, ok := e.internals.cache.data[cachename]
	e.internals.cache.mu.Unlock()
	if !ok {
		return fail.NotFoundError("Cache \"%s\" not found", cachename)
	}
	return store.Free(ctx, key)
}

func (e *ServiceTest) _cache_AddEntry(ctx context.Context, cachename string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	e._surveyf("ServiceTest::_cache_AddEntry { cache: \"%s\" } (not implemented)", cachename)
	e.internals.cache.mu.Lock()
	store, ok := e.internals.cache.data[cachename]
	e.internals.cache.mu.Unlock()
	if !ok {
		return nil, fail.NotFoundError("Cache \"%s\" not found", cachename)
	}
	return store.Add(ctx, content)
}
*/
// api.Stack
func (e *ServiceTest) GetStackName() (string, fail.Error) {
	if e.options.stacknameErr != nil {
		e._warnf("ServiceTest::GetStackName forced error \"%s\"", e.options.stacknameErr.Error())
		return "", e.options.stacknameErr
	}
	return e.options.stackname, nil
}
func (e *ServiceTest) ListAvailabilityZones(ctx context.Context) (map[string]bool, fail.Error) {
	e._survey("ServiceTest::ListAvailabilityZones (not implemented)")
	return map[string]bool{}, nil
}
func (e *ServiceTest) ListRegions(ctx context.Context) ([]string, fail.Error) {
	e._survey("ServiceTest::ListRegions (not implemented)")
	return []string{}, nil
}
func (e *ServiceTest) InspectImage(ctx context.Context, id string) (*abstract.Image, fail.Error) {
	e._survey("ServiceTest::InspectImage (not implemented)")
	return &abstract.Image{}, nil
}
func (e *ServiceTest) InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	e._log("ServiceTest::InspectTemplate (not implemented)")
	return &abstract.HostTemplate{}, nil
}

/* Key pairs */

func (e *ServiceTest) CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error) {
	e._logf("ServiceTest::CreateKeyPair { name: \"%s\"}", name)
	_, ok := e.memory.keypairs[name]
	if !ok {
		kp, xerr := abstract.NewKeyPair(name)
		if xerr != nil {
			return nil, xerr
		}
		e.memory.keypairs[name] = kp
	}
	return e.memory.keypairs[name], nil
}
func (e *ServiceTest) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	e._logf("ServiceTest::InspectKeyPair { name: \"%s\"}", id)
	_, ok := e.memory.keypairs[id]
	if !ok {
		return nil, fail.NotFoundError("KeyPair not found")
	}
	return e.memory.keypairs[id], nil
}
func (e *ServiceTest) ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error) {
	e._log("ServiceTest::ListKeyPairs")
	list := make([]*abstract.KeyPair, 0)
	for _, v := range e.memory.keypairs {
		list = append(list, v)
	}
	return list, nil
}
func (e *ServiceTest) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	e._logf("ServiceTest::DeleteKeyPair { name: \"%s\"}", id)
	_, ok := e.memory.keypairs[id]
	if !ok {
		return fail.NotFoundError("KeyPair not found")
	}
	delete(e.memory.keypairs, id)
	return nil
}

/* Securitygroups */

func (e *ServiceTest) _updateSecurityGroup(network string, name string, callback func(asg *abstract.SecurityGroup) *abstract.SecurityGroup) (ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	path1 := fmt.Sprintf("security-groups/byID/%s.%s", network, name)
	path2 := fmt.Sprintf("security-groups/byName/%s.%s", network, name)

	data, err := e._getInternalData(path1)
	if err != nil {
		data, err = e._getInternalData(path2)
		if err != nil {
			return fail.NotFoundError(fmt.Sprintf("Securitygroup \"%s\" not found", name))
		}
	}

	asg := &abstract.SecurityGroup{}
	err = json.Unmarshal([]byte(data), asg)
	if err != nil {
		return fail.Wrap(err)
	}

	asg = callback(asg)

	err = e._setInternalData(path1, asg)
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._setInternalData(path2, asg)
	if err != nil {
		return fail.Wrap(err)
	}

	return nil
}
func (e *ServiceTest) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	e._log("ServiceTest::ListSecurityGroups (not implemented)")
	return []*abstract.SecurityGroup{}, nil
}
func (e *ServiceTest) CreateSecurityGroup(ctx context.Context, networkRef string, name string, description string, rules abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error) {

	e._logf("ServiceTest::CreateSecurityGroup { name: \"%s\", description: \"%s\", network: \"%s\", rules: SecurityGroupRules(%d) }", name, description, networkRef, len(rules))

	asg := &abstract.SecurityGroup{
		ID:               fmt.Sprintf("%s.%s", networkRef, name),
		Name:             name, // fmt.Sprintf("%s.%s", networkRef, name), //name,
		Network:          networkRef,
		Description:      description,
		Rules:            rules,
		DefaultForSubnet: "",
		DefaultForHost:   "",
	}
	err := e._setInternalData(fmt.Sprintf("security-groups/byID/%s.%s", networkRef, name), asg)
	if err != nil {
		return nil, fail.DuplicateErrorWithCause(err, []error{}, fmt.Sprintf("SecurityGroup \"%s\" already exists", name))
	}
	err = e._setInternalData(fmt.Sprintf("security-groups/byName/%s.%s", networkRef, name), asg)
	if err != nil {
		return nil, fail.DuplicateErrorWithCause(err, []error{}, fmt.Sprintf("SecurityGroup \"%s\" already exists", name))
	}

	return asg, nil
}
func (e *ServiceTest) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return abstract.NewSecurityGroup(), xerr
	}
	return e.InspectSecurityGroupByName(ctx, asg.Name, asg.Network)
}
func (e *ServiceTest) InspectSecurityGroupByName(ctx context.Context, networkID string, name string) (asg *abstract.SecurityGroup, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	e._logf("ServiceTest::InspectSecurityGroupByName { networkId: \"%s\", name: \"%s\" }", networkID, name)

	if valid.IsNil(e) {
		e._log("ServiceTest::InspectSecurityGroup { label: ? }")
		return abstract.NewSecurityGroup(), fail.InvalidInstanceError()
	}
	data, err := e._getInternalData(fmt.Sprintf("security-groups/byID/%s.%s", networkID, name))
	if err != nil {
		data, err = e._getInternalData(fmt.Sprintf("security-groups/byName/%s.%s", networkID, name))
		if err != nil {
			return abstract.NewSecurityGroup(), fail.NotFoundError(fmt.Sprintf("Securitygroup \"%s\" not found", name))
		}
	}
	asg = &abstract.SecurityGroup{}
	err = json.Unmarshal([]byte(data), asg)
	if err != nil {
		return nil, fail.Wrap(err)
	}
	return asg, nil

}
func (e *ServiceTest) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		e._warn("ServiceTest::ClearSecurityGroup { name: ? }")
		return nil, xerr
	}
	e._logf("ServiceTest::ClearSecurityGroup { name: \"%s\" }", asg.Name)

	xerr = e._updateSecurityGroup(asg.Network, asg.Name, func(asg *abstract.SecurityGroup) *abstract.SecurityGroup {
		asg.Rules = abstract.SecurityGroupRules{}
		return asg
	})
	if xerr != nil {
		return nil, xerr
	}

	return asg, nil

}
func (e *ServiceTest) DeleteSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {

	e._logf("ServiceTest::DeleteSecurityGroup { name: \"%s\" }", asg.Name)
	err := e._deleteInternalData(fmt.Sprintf("security-groups/byID/%s.%s", asg.Network, asg.Name))
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._deleteInternalData(fmt.Sprintf("security-groups/byName/%s.%s", asg.Network, asg.Name))
	if err != nil {
		return fail.Wrap(err)
	}
	return nil

}
func (e *ServiceTest) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		e._log("ServiceTest::AddRuleToSecurityGroup { name: ?}")
		return nil, xerr
	}
	e._logf("ServiceTest::AddRuleToSecurityGroup { name: \"%s\" }", asg.Name)

	xerr = e._updateSecurityGroup(asg.Network, asg.Name, func(asg *abstract.SecurityGroup) *abstract.SecurityGroup {
		asg.Rules = append(asg.Rules, rule)
		return asg
	})

	return asg, xerr
}
func (e *ServiceTest) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		e._log("ServiceTest::DeleteRuleFromSecurityGroup { name: ?}")
		return nil, xerr
	}
	e._logf("ServiceTest::DeleteRuleFromSecurityGroup { name: \"%s\" }", asg.Name)

	xerr = e._updateSecurityGroup(asg.Network, asg.Name, func(asg *abstract.SecurityGroup) *abstract.SecurityGroup {
		rules := make([]*abstract.SecurityGroupRule, 0)
		for _, v := range asg.Rules {
			if !rule.EquivalentTo(v) {
				rules = append(rules, v)
			}
		}
		asg.Rules = rules
		return asg
	})
	return asg, xerr

}
func (e *ServiceTest) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	if e.options.defaultsgnameErr != nil {
		e._logf("ServiceTest::GetDefaultSecurityGroupName forced error \"%s\"", e.options.defaultsgnameErr.Error())
		return "", e.options.defaultsgnameErr
	}
	return e.options.defaultsgname, nil
}
func (e *ServiceTest) LookupRuleInSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup, asgr *abstract.SecurityGroupRule) (bool, fail.Error) {
	e._survey("ServiceTest::LookupRuleInSecurityGroup (not implemented)")
	return false, nil
}
func (e *ServiceTest) EnableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {

	name := asg.Name
	network := asg.Network
	e._surveyf("ServiceTest::EnableSecurityGroup { name: \"%s\" }", name)

	sg, xerr := LoadSecurityGroup(ctx, e, fmt.Sprintf("%s.%s", network, name))
	if xerr != nil {
		return xerr
	}
	return sg.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for hostId := range sghV1.ByID {
				sghV1.ByID[hostId].Disabled = false

			}
			return nil
		})
	})
}
func (e *ServiceTest) DisableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	name := asg.GetName()
	e._surveyf("ServiceTest::DisableSecurityGroup { name: \"%s\" }", name)

	if !e.options.candisablesecuritygroup {
		return fail.NotFoundError("Not able to disable securityGroup \"%s\", check GetCapabilities()", name)
	}

	sg, xerr := LoadSecurityGroup(ctx, e, name)
	if xerr != nil {
		return xerr
	}
	return sg.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for hostId := range sghV1.ByID {
				sghV1.ByID[hostId].Disabled = true
			}
			return nil
		})
	})
}
func (e *ServiceTest) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	// Load host
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		e._warn("ServiceTest::BindSecurityGroupToHost { sg: ?, host: ? }")
		return xerr
	}
	hostName := ahf.Core.Name
	if hostName == "" { // nolint
		hostName = ahf.Core.ID
	}
	if hostName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostname")
	}

	// Load securitygroup
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		e._warn("ServiceTest::BindSecurityGroupToHost { sg: ?, host: ? }")
		return xerr
	}
	asgName := fmt.Sprintf("%s.%s", asg.Network, asg.Name)
	if asg.Network == "" || asg.Name == "" {
		asgName = sgLabel
	}

	e._logf("ServiceTest::BindSecurityGroupToHost { sgName: \"%s\", host: \"%s\" }", asgName, hostName)

	sgb := &propertiesv1.SecurityGroupBond{
		ID:       hostName,
		Name:     hostName,
		Disabled: true,
	}

	// sg > host
	sg, xerr := LoadSecurityGroup(ctx, e, asgName)
	if xerr != nil {
		return xerr
	}
	return sg.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			sghV1.ByID[hostName] = sgb
			sghV1.ByName[hostName] = hostName
			return nil
		})
	})
}
func (e *ServiceTest) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	// Load host
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		e._warn("ServiceTest::UnbindSecurityGroupFromHost { sg: ?, host: ? }")
		return xerr
	}
	hostName := ahf.Core.Name
	if hostName == "" { // nolint
		hostName = ahf.Core.ID
	}
	if hostName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostname")
	}

	// Load securitygroup
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		e._warn("ServiceTest::UnbindSecurityGroupFromHost { sg: ?, host: ? }")
		return xerr
	}
	asgName := fmt.Sprintf("%s.%s", asg.Network, asg.Name)
	if asg.Network == "" || asg.Name == "" {
		asgName = sgLabel
	}

	e._logf("ServiceTest::UnbindSecurityGroupFromHost { sgName: \"%s\", host: \"%s\" }", asgName, hostName)

	sg, xerr := LoadSecurityGroup(ctx, e, asgName)
	if xerr != nil {
		return xerr
	}
	return sg.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if len(sghV1.ByID) > 0 {
				_, ok = sghV1.ByID[hostName]
				if ok {
					delete(sghV1.ByID, hostName)
				}
			}
			if len(sghV1.ByName) > 0 {
				_, ok = sghV1.ByName[hostName]
				if ok {
					delete(sghV1.ByName, hostName)
				}
			}
			return nil
		})
	})

}

/* Networks */

func (e *ServiceTest) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (an *abstract.Network, ferr fail.Error) {
	e._logf("ServiceTest::CreateNetwork { name: \"%s\", CIDR: \"%s\" }", req.Name, req.CIDR)

	defer fail.OnPanic(&ferr)

	anetwork := &abstract.Network{
		ID:         req.Name,
		Name:       req.Name,
		CIDR:       req.CIDR,
		Imported:   false,
		DNSServers: req.DNSServers,
		Tags: map[string]string{
			"CreationDate": time.Now().Format(time.RFC3339),
			"ManagedBy":    "safescale",
		},
	}

	// Pre-save network
	err := e._setInternalData(fmt.Sprintf("networks/byID/%s", req.Name), anetwork)
	if err != nil {
		return nil, fail.DuplicateErrorWithCause(err, []error{}, fmt.Sprintf("Network %s already exists", req.Name))
	}
	err = e._setInternalData(fmt.Sprintf("networks/byName/%s", req.Name), anetwork)
	if err != nil {
		return nil, fail.DuplicateErrorWithCause(err, []error{}, fmt.Sprintf("Network %s already exists", req.Name))
	}

	// abstract.CreateNetwork to resources.CreateNetwork
	network, xerr := NewCore(e, "network", "networks", anetwork)
	if xerr != nil {
		return anetwork, xerr
	}
	xerr = network.Carry(ctx, anetwork)
	if xerr != nil {
		return anetwork, xerr
	}

	xerr = network.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {

		// networkproperty.DescriptionV1    = "1" // contains optional additional info describing Networking (purpose, ...)
		// networkproperty.HostsV1          = "2" // OBSOLETE: moved to subnetproperty: contains list of hosts attached to the network
		// networkproperty.SubnetsV1        = "3" // contains the subnets created in the Network
		// networkproperty.SingleHostsV1    = "4" // contains the CIDRs usable for single Hosts
		// networkproperty.SecurityGroupsV1 = "5" // contains the Security Groups owned by the Network

		xerr = props.Alter(networkproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {

			networkDescriptionV1, ok := clonable.(*propertiesv1.NetworkDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// networkDescriptionV1.Domain
			networkDescriptionV1.Purpose = "Test"
			networkDescriptionV1.Created = time.Now()

			return nil
		})
		if xerr != nil {
			return xerr
		}

		return nil
	})

	return anetwork, nil

}
func (e *ServiceTest) InspectNetwork(ctx context.Context, id string) (an *abstract.Network, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	data, err := e._getInternalData(fmt.Sprintf("networks/byID/%s", id))
	if err != nil { // nolint
		data, err = e._getInternalData(fmt.Sprintf("networks/byName/%s", id))
	}
	if err != nil {
		e._warnf("ServiceTest::InspectNetwork { id: %s } not found !", id)
		return nil, fail.NotFoundError(err.Error())
	}
	e._logf("ServiceTest::InspectNetwork { id: %s }", id)
	an = &abstract.Network{}
	err = json.Unmarshal([]byte(data), an)
	if err != nil {
		return nil, fail.Wrap(err)
	}
	return an, nil
}
func (e *ServiceTest) InspectNetworkByName(ctx context.Context, name string) (an *abstract.Network, ferr fail.Error) {
	e._logf("ServiceTest::InspectNetworkByName { name: %s }", name)

	defer fail.OnPanic(&ferr)

	data, err := e._getInternalData(fmt.Sprintf("networks/byName/%s", name))
	if err != nil {
		e.internals.t.Error(err)
		return nil, fail.NotFoundError(err.Error())
	}

	an = &abstract.Network{}
	err = json.Unmarshal([]byte(data), an)
	if err != nil {
		return nil, fail.Wrap(err)
	}
	return an, nil

}
func (e *ServiceTest) DeleteNetwork(ctx context.Context, id string) fail.Error {
	e._logf("ServiceTest::DeleteNetwork { name: \"%s\" }", id)
	err := e._deleteInternalData(fmt.Sprintf("networks/byID/%s", id))
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._deleteInternalData(fmt.Sprintf("networks/byName/%s", id))
	if err != nil {
		return fail.Wrap(err)
	}
	return nil
}
func (e *ServiceTest) HasDefaultNetwork(ctx context.Context) (bool, fail.Error) {
	e._log("ServiceTest::HasDefaultNetwork (no)")
	return false, nil
}
func (e *ServiceTest) GetDefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	e._survey("ServiceTest::GetDefaultNetwork (not implemented)")
	return nil, nil
}

/* Subnet */

func (e *ServiceTest) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (as *abstract.Subnet, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	e._logf("ServiceTest::CreateSubnet { NetworkID: \"%s\", Name: \"%s\", IPVersion: \"%s\", CIDR: \"%s\" }", req.NetworkID, req.Name, req.IPVersion.String(), req.CIDR)

	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	if xerr != nil {
		return nil, xerr
	}

	v := abstract.NewVirtualIP()
	v.ID = "VirtualIP ID"
	v.Name = "VirtualIP Name"
	v.SubnetID = "VirtualIP SubnetID"
	v.PrivateIP = "VirtualIP PrivateIP"
	v.PublicIP = "VirtualIP PublicIP"
	v.Hosts = []*abstract.HostCore{abstract.NewHostCore()}
	v.NetworkID = req.NetworkID

	// Create subnet
	as = &abstract.Subnet{
		ID:         req.Name,
		Name:       req.Name,
		Network:    req.NetworkID,
		CIDR:       req.CIDR,
		GatewayIDs: make([]string, 0),
		VIP:        v,
		// State: subnetstate.Unknown,
		// GWSecurityGroupID: "",
		// PublicIPSecurityGroupID: "",
		// InternalSecurityGroupID: "",
		Domain:         req.Domain,
		DNSServers:     req.DNSServers,
		IPVersion:      req.IPVersion,
		DefaultSSHPort: req.DefaultSSHPort,
		// SingleHostCIDRIndex: 0
		Tags: map[string]string{
			"CreationDate": time.Now().Format(time.RFC3339),
			"ManagedBy":    "safescale",
		},
	}

	// Pre-save host core
	err := e._setInternalData(fmt.Sprintf("subnets/byID/%s", as.ID), as)
	if err != nil {
		return as, fail.Wrap(err)
	}
	err = e._setInternalData(fmt.Sprintf("subnets/byName/%s", as.Name), as)
	if err != nil {
		return as, fail.Wrap(err)
	}

	// abstract.Subnet to resources.Subnet
	subnet, xerr := NewCore(e, "subnet", "subnets", as)
	if xerr != nil {
		return as, xerr
	}
	xerr = subnet.Carry(ctx, as)
	if xerr != nil {
		return as, xerr
	}

	xerr = subnet.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {

		/*
			 xerr = props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {

				 ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
				 if !ok {
					 return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
				 }

				 ssgV1.ByName[hostName] = hostID // <<< link to sgr
				 ssgV1.ByID[hostID] = hostName // <<< link to sgr


				 return nil
			 })
			 if xerr != nil {
				 return xerr
			 }
		*/

		/*
			 xerr = props.Alter(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {

				 subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
				 if !ok {
					 return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				 }

				 subnetHostsV1.ByName[hostName] = hostID // <<< link to host
				 subnetHostsV1.ByID[hostID] = hostName // <<< link to host
				 return nil

				 return nil
			 })
			 if xerr != nil {
				 return xerr
			 }
		*/

		xerr = props.Alter(subnetproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
			subnetDescriptionV1, ok := clonable.(*propertiesv1.SubnetDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			subnetDescriptionV1.Domain = req.Domain
			subnetDescriptionV1.Purpose = "Test"
			subnetDescriptionV1.Created = time.Now()
			return nil
		})
		if xerr != nil {
			return xerr
		}

		return nil

	})

	// Load related network
	network, xerr := LoadNetwork(ctx, e, req.NetworkID)
	if xerr != nil {
		return nil, xerr
	}

	// Link subnet to network
	xerr = network.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			subnetsV1.ByName[req.Name] = req.Name
			return nil
		})
	})

	return as, nil
}
func (e *ServiceTest) InspectSubnet(ctx context.Context, id string) (asn *abstract.Subnet, ferr fail.Error) {

	e._logf("ServiceTest::InspectSubnet { id: %s }", id)

	defer fail.OnPanic(&ferr)

	data, err := e._getInternalData(fmt.Sprintf("subnets/byID/%s", id))
	if err != nil {
		data, err = e._getInternalData(fmt.Sprintf("subnets/byName/%s", id))
		if err != nil {
			return nil, fail.NotFoundError(err.Error())
		}
	}

	asn = &abstract.Subnet{}
	err = json.Unmarshal([]byte(data), asn)
	if err != nil {
		return nil, fail.Wrap(err)
	}
	return asn, nil

}
func (e *ServiceTest) InspectSubnetByName(ctx context.Context, networkID string, name string) (asn *abstract.Subnet, ferr fail.Error) {
	e._surveyf("ServiceTest::InspectSubnetByName { network: \"%s\", name: \"%s\" }", networkID, name)

	defer fail.OnPanic(&ferr)

	data, err := e._getInternalData(fmt.Sprintf("subnets/byID/%s", name))
	if err != nil {
		data, err = e._getInternalData(fmt.Sprintf("subnets/byName/%s", name))
		if err != nil {
			return nil, fail.NotFoundError(err.Error())
		}
	}

	asn = &abstract.Subnet{}
	err = json.Unmarshal([]byte(data), asn)
	if err != nil {
		return nil, fail.Wrap(err)
	}
	return asn, nil

}
func (e *ServiceTest) ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error) {
	e._survey("ServiceTest::ListSubnets (not implemented)")
	return []*abstract.Subnet{}, nil
}
func (e *ServiceTest) DeleteSubnet(ctx context.Context, id string) fail.Error {

	e._logf("ServiceTest::DeleteSubnet { id: %s }", id)

	err := e._deleteInternalData(fmt.Sprintf("subnets/byID/%s", id))
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._deleteInternalData(fmt.Sprintf("subnets/byName/%s", id))
	if err != nil {
		return fail.Wrap(err)
	}
	return nil
}

/* VIP */

func (e *ServiceTest) CreateVIP(_ context.Context, networkID string, subnetID string, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	e._survey("ServiceTest::CreateVIP (not implemented)")
	return nil, nil
}
func (e *ServiceTest) AddPublicIPToVIP(_ context.Context, vip *abstract.VirtualIP) fail.Error {
	e._survey("ServiceTest::AddPublicIPToVIP (not implemented)")
	return nil
}
func (e *ServiceTest) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, target string) fail.Error {
	e._survey("ServiceTest::BindHostToVIP (not implemented)")
	return nil
}
func (e *ServiceTest) UnbindHostFromVIP(_ context.Context, vip *abstract.VirtualIP, target string) fail.Error {
	e._survey("ServiceTest::UnbindHostFromVIP (not implemented)")
	return nil
}
func (e *ServiceTest) DeleteVIP(_ context.Context, vip *abstract.VirtualIP) fail.Error {
	e._survey("ServiceTest::DeleteVIP (not implemented)")
	return nil
}

/* Host */

func (e *ServiceTest) CreateHostWithKeyPair(ctx context.Context, request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, *abstract.KeyPair, fail.Error) {

	name := request.ResourceName
	e._logf("ServiceTest::CreateHostWithKeyPair { name: \"%s\"}", name)

	// Create temporary key pair
	kpNameuuid, err := uuid.NewV4()
	if err != nil {
		return nil, nil, nil, fail.ConvertError(err)
	}

	kpName := kpNameuuid.String()
	kp, rerr := e.CreateKeyPair(ctx, kpName)
	if rerr != nil {
		return nil, nil, nil, rerr
	}

	// Create host
	hostReq := abstract.HostRequest{
		ResourceName:   request.ResourceName,
		HostName:       request.HostName,
		ImageID:        request.ImageID,
		ImageRef:       request.ImageID,
		KeyPair:        kp,
		PublicIP:       request.PublicIP,
		Subnets:        request.Subnets,
		DefaultRouteIP: request.DefaultRouteIP,
		DiskSize:       request.DiskSize,
		// DefaultGateway: request.DefaultGateway,
		TemplateID: request.TemplateID,
	}
	hf, udc, xerr := e.CreateHost(ctx, hostReq)
	return hf, udc, kp, xerr
}

func (e *ServiceTest) CreateHost(ctx context.Context, request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {

	if valid.IsNil(request) {
		return nil, nil, fail.InvalidParameterCannotBeNilError("request")
	}
	name := request.ResourceName
	e._logf("ServiceTest::CreateHost { name: \"%s\"}", name)

	uc := &userdata.Content{
		IsGateway:       request.IsGateway,
		FinalPrivateKey: "",
	}

	privateKey, _, xerr := crypt.GenerateRSAKeyPair("Service-Test." + request.HostName)
	if xerr != nil {
		return nil, uc, fail.Wrap(xerr)
	}
	uc.FinalPrivateKey = privateKey

	ip4 := request.DefaultRouteIP
	wds := strings.Split(ip4, ".")
	ip6 := "0:0:0:0:0:ffff:"
	hex := [16]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	bytes := [4]byte{0, 0, 0, 0}
	for i := range bytes {
		if i < len(wds) {
			i64, _ := strconv.ParseInt(wds[i], 10, 8)
			bytes[i] = byte(i64)
		}
		ip6 = ip6 + hex[((bytes[i]&240)>>4)] + hex[(bytes[i]&15)]
		if i == 1 {
			ip6 += ":"
		}
	}

	if len(request.Subnets) == 0 {
		if !e._hasInternalData(fmt.Sprintf("networks/ByID/%s", name)) {
			_, xerr = e.CreateNetwork(ctx, abstract.NetworkRequest{
				Name:          name,
				CIDR:          ip4 + "/24",
				DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
				KeepOnFailure: false,
			})
			if xerr != nil {
				return nil, uc, fail.Wrap(xerr)
			}
		}
		if !e._hasInternalData(fmt.Sprintf("subnets/ByID/%s", name)) {
			as, xerr := e.CreateSubnet(ctx, abstract.SubnetRequest{
				NetworkID:      name,
				Name:           name,
				IPVersion:      ipversion.IPv4,
				CIDR:           ip4 + "/28",
				DNSServers:     []string{"8.8.8.8", "8.8.4.4"},
				Domain:         "Domain",
				HA:             false,
				ImageRef:       "",
				DefaultSSHPort: 22,
				KeepOnFailure:  false,
			})
			if xerr != nil {
				return nil, uc, fail.Wrap(xerr)
			}
			request.Subnets = []*abstract.Subnet{as}
		}
	}

	ahf := &abstract.HostFull{
		Core: &abstract.HostCore{
			ID:                name,
			Name:              name,
			PrivateKey:        privateKey,
			SSHPort:           22,
			Password:          request.Password,
			LastState:         hoststate.Stopped,
			ProvisioningState: hoststate.Unknown,
			Tags: map[string]string{
				"CreationDate": time.Now().Format(time.RFC3339),
				"ManagedBy":    "safescale",
			},
		},
		Sizing: &abstract.HostEffectiveSizing{
			Cores:       1,
			RAMSize:     1024.0,
			DiskSize:    request.DiskSize,
			GPUNumber:   1,
			GPUType:     "Nvidia RTX 3080",
			CPUFreq:     4033.0,
			ImageID:     "",
			Replaceable: false,
		},
		Networking: &abstract.HostNetworking{
			IsGateway:               request.IsGateway,
			DefaultGatewayID:        "",
			DefaultGatewayPrivateIP: request.DefaultRouteIP,
			DefaultSubnetID:         name,
			SubnetsByID:             map[string]string{name: name},
			SubnetsByName:           map[string]string{name: name},
			PublicIPv4:              ip4,
			PublicIPv6:              ip6,
			IPv4Addresses:           map[string]string{name: ip4},
			IPv6Addresses:           map[string]string{name: ip6},
		},
		Description: &abstract.HostDescription{
			Created: time.Now(),
			Creator: "ServiceTest",
			Updated: time.Now(),
			Purpose: "UT-Test",
			Tenant:  "Test",
		},
		CurrentState: hoststate.Stopped,
	}
	if len(request.Subnets) > 0 {
		ahf.Networking.SubnetsByID = make(map[string]string)
		ahf.Networking.SubnetsByName = make(map[string]string)
		ahf.Networking.IPv4Addresses = make(map[string]string)
		ahf.Networking.IPv6Addresses = make(map[string]string)
		for _, subnet := range request.Subnets {
			ahf.Networking.SubnetsByID[subnet.Name] = subnet.Name
			ahf.Networking.SubnetsByName[subnet.Name] = subnet.Name
			ahf.Networking.IPv4Addresses[subnet.Name] = ip4
			ahf.Networking.IPv4Addresses[subnet.Name] = ip6
		}
	}

	// Pre-save host core
	err := e._setInternalData(fmt.Sprintf("hosts/byID/%s", name), ahf.Core)
	if err != nil {
		return ahf, uc, fail.Wrap(err)
	}
	err = e._setInternalData(fmt.Sprintf("hosts/byName/%s", name), ahf.Core)
	if err != nil {
		return ahf, uc, fail.Wrap(err)
	}

	// abstract.HostFull to resources.host
	host, xerr := NewCore(e, "host", "hosts", ahf.Core)
	if xerr != nil {
		return ahf, uc, xerr
	}
	xerr = host.Carry(ctx, ahf.Core)
	if xerr != nil {
		return ahf, uc, xerr
	}

	if !request.IsGateway {
		_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
			ResourceName: fmt.Sprintf("gw-%s", name),
			HostName:     fmt.Sprintf("gw-%s", name),
			ImageID:      request.ImageID,
			ImageRef:     "",
			PublicIP:     false,
			Single:       true,
			Subnets:      make([]*abstract.Subnet, 0),
			// Subnets:        []*abstract.Subnet{request.Subnets[0]},
			DefaultRouteIP: ip6,
			DiskSize:       64,
			SSHPort:        22,
			// KeyPair		: ,
			TemplateID:  request.TemplateID,
			TemplateRef: "",
			IsGateway:   true,
		})
		_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
			ResourceName: fmt.Sprintf("gw2-%s", name),
			HostName:     fmt.Sprintf("gw2-%s", name),
			ImageID:      request.ImageID,
			ImageRef:     "",
			PublicIP:     false,
			Single:       true,
			Subnets:      make([]*abstract.Subnet, 0),
			// Subnets:        []*abstract.Subnet{request.Subnets[0]},
			DefaultRouteIP: ip6,
			DiskSize:       64,
			SSHPort:        22,
			// KeyPair		: ,
			TemplateID:  request.TemplateID,
			TemplateRef: "",
			IsGateway:   true,
		})
	}

	xerr = host.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {

		xerr = props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
			hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostSizingV2.AllocatedSize = &propertiesv2.HostEffectiveSizing{
				Cores:     ahf.Sizing.Cores,
				RAMSize:   ahf.Sizing.RAMSize,
				DiskSize:  ahf.Sizing.DiskSize,
				GPUNumber: ahf.Sizing.GPUNumber,
				GPUType:   ahf.Sizing.GPUType,
				CPUFreq:   ahf.Sizing.CPUFreq,
			}
			hostSizingV2.RequestedSize = &propertiesv2.HostSizingRequirements{
				MinCores:    ahf.Sizing.Cores,
				MaxCores:    ahf.Sizing.Cores,
				MinRAMSize:  ahf.Sizing.RAMSize,
				MaxRAMSize:  ahf.Sizing.RAMSize,
				MinDiskSize: ahf.Sizing.DiskSize,
				MinGPU:      ahf.Sizing.GPUNumber,
				MinCPUFreq:  ahf.Sizing.CPUFreq,
				Replaceable: ahf.Sizing.Replaceable,
			}
			hostSizingV2.Template = request.TemplateRef
			return nil
		})
		if xerr != nil {
			return xerr
		}

		xerr = props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			network, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			network.DefaultSubnetID = ahf.Networking.DefaultSubnetID
			network.PublicIPv4 = ahf.Networking.PublicIPv4
			network.PublicIPv6 = ahf.Networking.PublicIPv6
			network.SubnetsByID = ahf.Networking.SubnetsByID
			network.SubnetsByName = ahf.Networking.SubnetsByName
			network.IPv4Addresses = ahf.Networking.IPv4Addresses
			network.IPv6Addresses = ahf.Networking.IPv6Addresses
			network.IsGateway = ahf.Networking.IsGateway
			network.Single = request.Single
			return nil
		})
		if xerr != nil {
			return xerr
		}

		xerr = props.Alter(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
			description, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			description.Created = ahf.Description.Created
			description.Creator = ahf.Description.Creator
			description.Updated = ahf.Description.Updated
			description.Purpose = ahf.Description.Purpose
			description.Tenant = ahf.Description.Tenant
			description.Domain = "test-domain"
			return nil
		})
		if xerr != nil {
			return xerr
		}

		return nil
	})
	if xerr != nil {
		return ahf, uc, xerr
	}
	// _ = host.Reload(ctx)

	return ahf, uc, nil
}
func (e *ServiceTest) ClearHostStartupScript(context.Context, stacks.HostParameter) fail.Error {
	e._survey("ServiceTest::ClearHostStartupScript (do nothing)")
	return nil
}
func (e *ServiceTest) InspectHost(ctx context.Context, params stacks.HostParameter) (hf *abstract.HostFull, ferr fail.Error) {

	if valid.IsNil(e) {
		e._error("ServiceTest::InspectHost (error)")
		return abstract.NewHostFull(), fail.InvalidInstanceError()
	}
	var xerr fail.Error
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, params)

	if xerr != nil {
		e._error("ServiceTest::InspectHost (error)")
		return abstract.NewHostFull(), xerr
	}
	id := ahf.Core.ID
	if id == "" {
		id = ahf.Core.Name
	}
	return e.InspectHostByName(ctx, id)

}
func (e *ServiceTest) InspectHostByName(ctx context.Context, name string) (ahf *abstract.HostFull, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	e._logf("ServiceTest::InspectHostByName { name: \"%s\" }", name)

	ahf = abstract.NewHostFull()
	serial, err := e._getInternalData(fmt.Sprintf("hosts/byID/%s", name))
	if err != nil {
		serial, err = e._getInternalData(fmt.Sprintf("hosts/byName/%s", name))
		if err != nil {
			return ahf, fail.NotFoundError(fmt.Sprintf("host \"%s\" not found", name))
		}
	}
	hc := &abstract.HostCore{LastState: hoststate.Unknown}
	err = json.Unmarshal([]byte(serial), &hc)
	if err != nil {
		return ahf, fail.Wrap(err)
	}
	ahf.Core = hc

	host, xerr := NewCore(e, "host", "hosts", ahf.Core)
	if xerr != nil {
		return ahf, xerr
	}
	xerr = host.Carry(ctx, hc)
	if xerr != nil {
		return ahf, xerr
	}

	xerr = host.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {

		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("*abstract.HostCores' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		ahf.Core = ahc

		xerr = props.Inspect(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
			hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			ahf.Sizing.Cores = hostSizingV2.AllocatedSize.Cores
			ahf.Sizing.RAMSize = hostSizingV2.AllocatedSize.RAMSize
			ahf.Sizing.DiskSize = hostSizingV2.AllocatedSize.DiskSize
			ahf.Sizing.GPUNumber = hostSizingV2.AllocatedSize.GPUNumber
			ahf.Sizing.GPUType = hostSizingV2.AllocatedSize.GPUType
			ahf.Sizing.CPUFreq = hostSizingV2.AllocatedSize.CPUFreq
			ahf.Sizing.ImageID = ""
			ahf.Sizing.Replaceable = false
			return nil
		})
		if xerr != nil {
			return xerr
		}

		xerr = props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			network, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			ahf.Networking.IsGateway = network.IsGateway
			ahf.Networking.DefaultGatewayID = fmt.Sprintf("gw-%s", name)
			ahf.Networking.DefaultGatewayPrivateIP = network.PublicIPv6
			ahf.Networking.DefaultSubnetID = network.DefaultSubnetID
			ahf.Networking.SubnetsByID = network.SubnetsByID
			ahf.Networking.SubnetsByName = network.SubnetsByName
			ahf.Networking.PublicIPv4 = network.PublicIPv4
			ahf.Networking.PublicIPv6 = network.PublicIPv6
			ahf.Networking.IPv4Addresses = network.IPv4Addresses
			ahf.Networking.IPv6Addresses = network.IPv6Addresses
			return nil
		})
		if xerr != nil {
			return xerr
		}

		xerr = props.Alter(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
			description, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			ahf.Description.Created = description.Created
			ahf.Description.Creator = description.Creator
			ahf.Description.Updated = description.Updated
			ahf.Description.Purpose = description.Purpose
			ahf.Description.Tenant = description.Tenant
			return nil
		})
		if xerr != nil {
			return xerr
		}

		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	ahf.CurrentState = ahf.Core.LastState

	return ahf, nil
}
func (e *ServiceTest) GetHostState(context.Context, stacks.HostParameter) (hoststate.Enum, fail.Error) {
	e._survey("ServiceTest::GetHostState (not implemented)")
	return hoststate.Enum(0), nil
}
func (e *ServiceTest) ListHosts(context.Context, bool) (abstract.HostList, fail.Error) {
	e._survey("ServiceTest::ListHosts (not implemented)")
	return abstract.HostList{}, nil
}
func (e *ServiceTest) DeleteHost(ctx context.Context, params stacks.HostParameter) fail.Error {

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, params)
	if xerr != nil {
		e._warn("ServiceTest::DeleteHost { name: ? }")
		return xerr
	}
	name := ahf.Core.Name
	if name == "" {
		e._warn("ServiceTest::DeleteHost { name: ? }")
		return fail.NotFoundError(fmt.Sprintf("host \"%s\" not found", name))
	}

	e._logf("ServiceTest::DeleteHost { name: %s }", name)

	err := e._deleteInternalData(fmt.Sprintf("hosts/byID/%s", name))
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._deleteInternalData(fmt.Sprintf("hosts/byName/%s", name))
	if err != nil {
		return fail.Wrap(err)
	}

	return nil
}
func (e *ServiceTest) StopHost(ctx context.Context, params stacks.HostParameter, gracefully bool) fail.Error {

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, params)
	if xerr != nil {
		e._warn("ServiceTest::StopHost { name: ? } (emulated)")
		return xerr
	}
	name := ahf.Core.Name
	if name == "" { // nolint
		name = ahf.Core.ID
	}
	if name == "" {
		e._warn("ServiceTest::StopHost { name: ? } (emulated)")
		return fail.NotFoundError(fmt.Sprintf("host \"%s\" not found", name))
	}
	e._surveyf("ServiceTest::StopHost { name: \"%s\" } (emulated)", name)

	// Update state
	rhost, xerr := LoadHost(ctx, e, name)
	if xerr != nil {
		return xerr
	}
	xerr = rhost.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		ahc.LastState = hoststate.Stopped
		return nil
	})
	if xerr != nil {
		return xerr
	}

	return nil
}
func (e *ServiceTest) StartHost(ctx context.Context, params stacks.HostParameter) fail.Error {

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, params)
	if xerr != nil {
		e._warn("ServiceTest::StartHost { name: ? } (emulated)")
		return xerr
	}

	name := ahf.Core.Name
	if name == "" { // nolint
		name = ahf.Core.ID
	}
	if name == "" {
		e._warn("ServiceTest::StartHost { name: ? } (emulated)")
		return fail.NotFoundError(fmt.Sprintf("host \"%s\" not found", name))
	}
	e._surveyf("ServiceTest::StartHost { name: \"%s\" } (emulated)", name)

	// Update state
	rhost, xerr := LoadHost(ctx, e, name)
	if xerr != nil {
		return xerr
	}
	return rhost.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		ahc.LastState = hoststate.Started
		return nil
	})

}
func (e *ServiceTest) RebootHost(context.Context, stacks.HostParameter) fail.Error {
	e._survey("ServiceTest::RebootHost (not implemented)")
	return nil
}
func (e *ServiceTest) ResizeHost(context.Context, stacks.HostParameter, abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	e._survey("ServiceTest::ResizeHost (not implemented)")
	return nil, nil
}
func (e *ServiceTest) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	e._survey("ServiceTest::WaitHostReady (not implemented)")
	return nil, nil
}

/* Cluster */
func (e *ServiceTest) _CreateCluster(ctx context.Context, request abstract.ClusterRequest, shorten bool) (*abstract.ClusterIdentity, fail.Error) { // nolint

	var (
		name string
		xerr fail.Error
		err  error
	)

	// Context
	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}
	ctx = context.WithValue(ctx, "task", task)

	// In param control
	if valid.IsNil(request) {
		return nil, fail.InvalidParameterCannotBeNilError("request")
	}

	// Init
	name = request.Name
	e._logf("ServiceTest::_CreateCluster { name: \"%s\"}", name)

	// Make abstract.cluster
	kpName := "cluster_" + name + "_cladm_key"
	kp, xerr := e.CreateKeyPair(ctx, kpName)
	if xerr != nil {
		return nil, xerr
	}
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return &abstract.ClusterIdentity{}, fail.ConvertError(err)
	}
	aci := &abstract.ClusterIdentity{
		Name:          name,
		Flavor:        request.Flavor,
		Complexity:    request.Complexity,
		Keypair:       kp,
		AdminPassword: cladmPassword,
		Tags: map[string]string{
			"CreationDate": time.Now().Format(time.RFC3339),
			"ManagedBy":    "safescale",
		},
	}

	// Cluster network
	if !e._hasInternalData(fmt.Sprintf("networks/ByID/%s", request.NetworkID)) {
		_, xerr = e.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          request.NetworkID,
			CIDR:          request.CIDR,
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		if xerr != nil {
			return aci, xerr
		}
	}
	network, xerr := e.InspectNetwork(ctx, request.NetworkID)
	if xerr != nil {
		return aci, xerr
	}

	// Cluster subnet
	if !e._hasInternalData(fmt.Sprintf("subnets/ByID/%s", name)) {
		_, xerr := e.CreateSubnet(ctx, abstract.SubnetRequest{
			NetworkID:      network.ID,
			Name:           name,
			IPVersion:      network.IPVersion,
			CIDR:           network.CIDR,
			DNSServers:     network.DNSServers,
			Domain:         request.Domain,
			HA:             false,
			ImageRef:       "",
			DefaultSSHPort: 22,
			KeepOnFailure:  false,
		})
		if xerr != nil {
			return aci, xerr
		}
	}
	subnet, xerr := e.InspectSubnet(ctx, name)
	if xerr != nil {
		return aci, xerr
	}

	// Cluster securityGroups
	sgNames := []string{"PublicIPSecurityGroupID", "GWSecurityGroupID", "InternalSecurityGroupID"}
	for _, sgName := range sgNames {
		if !e._hasInternalData(fmt.Sprintf("security-groups/byID/%s.%s", network.ID, sgName)) {
			_, xerr := e.CreateSecurityGroup(ctx, network.ID, sgName, fmt.Sprintf("Sg desc %s", sgName), abstract.SecurityGroupRules{
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "icmp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "tcp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "udp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
			})
			if xerr != nil {
				return aci, xerr
			}
		}
	}

	// Cluster gateway
	if !e._hasInternalData(fmt.Sprintf("hosts/ByID/gw-%s", name)) {
		_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   fmt.Sprintf("gw-%s", name),
			HostName:       fmt.Sprintf("gw-%s", name),
			Subnets:        []*abstract.Subnet{subnet},
			DefaultRouteIP: "192.168.0.1",
			TemplateID:     request.GatewaysDef.Template,
			// TemplateRef
			ImageID: request.GatewaysDef.Image,
			// ImageRef
			KeyPair:       kp,
			SSHPort:       22,
			Password:      cladmPassword,
			DiskSize:      64,
			Single:        false,
			PublicIP:      true,
			IsGateway:     true,
			KeepOnFailure: false,
			Preemptible:   false,
			SecurityGroupIDs: map[string]struct{}{
				"PublicIPSecurityGroupID": {},
				"GWSecurityGroupID":       {},
				"InternalSecurityGroupID": {},
			},
		})
		if xerr != nil {
			return aci, xerr
		}
		gw, xerr := LoadHost(ctx, e, fmt.Sprintf("gw-%s", name))
		if xerr != nil {
			return aci, xerr
		}
		xerr = gw.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			_, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hnV2.PublicIPv4 = "192.168.11.11"
				hnV2.PublicIPv6 = ""

				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			return nil
		})
	}
	if !e._hasInternalData(fmt.Sprintf("hosts/ByID/gw2-%s", name)) {
		_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   fmt.Sprintf("gw2-%s", name),
			HostName:       fmt.Sprintf("gw2-%s", name),
			Subnets:        []*abstract.Subnet{subnet},
			DefaultRouteIP: "192.168.0.2",
			TemplateID:     request.GatewaysDef.Template,
			// TemplateRef
			ImageID: request.GatewaysDef.Image,
			// ImageRef
			KeyPair:       kp,
			SSHPort:       22,
			Password:      cladmPassword,
			DiskSize:      64,
			Single:        false,
			PublicIP:      true,
			IsGateway:     true,
			KeepOnFailure: false,
			Preemptible:   false,
			SecurityGroupIDs: map[string]struct{}{
				"PublicIPSecurityGroupID": {},
				"GWSecurityGroupID":       {},
				"InternalSecurityGroupID": {},
			},
		})
		if xerr != nil {
			return aci, xerr
		}
		gw, xerr := LoadHost(ctx, e, fmt.Sprintf("gw2-%s", name))
		if xerr != nil {
			return aci, xerr
		}
		xerr = gw.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			_, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hnV2.PublicIPv4 = "192.168.11.12"
				hnV2.PublicIPv6 = ""

				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			return nil
		})
	}

	if shorten { // To make cluster.Create result without have to folow procedure

		// Cluster master subnet
		if !e._hasInternalData(fmt.Sprintf("subnets/ByID/%s-master-1", name)) {
			_, xerr := e.CreateSubnet(ctx, abstract.SubnetRequest{
				NetworkID:      network.ID,
				Name:           fmt.Sprintf("%s-master-1", name),
				IPVersion:      network.IPVersion,
				CIDR:           network.CIDR,
				DNSServers:     network.DNSServers,
				Domain:         request.Domain,
				HA:             false,
				ImageRef:       "",
				DefaultSSHPort: 22,
				KeepOnFailure:  false,
			})
			if xerr != nil {
				return aci, xerr
			}
			rsubnet, xerr := LoadSubnet(ctx, e, request.NetworkID, fmt.Sprintf("%s-master-1", name))
			if xerr != nil {
				return aci, xerr
			}
			xerr = rsubnet.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				as.GatewayIDs = []string{fmt.Sprintf("gw-%s", name), fmt.Sprintf("gw2-%s", name)}
				return nil
			})
			if xerr != nil {
				return aci, xerr
			}
		}
		mastersubnet, xerr := e.InspectSubnet(ctx, name)
		if xerr != nil {
			return aci, xerr
		}

		// Cluster master
		if !e._hasInternalData(fmt.Sprintf("hosts/ByID/%s-master-1", name)) {
			_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
				ResourceName:   fmt.Sprintf("%s-master-1", name),
				HostName:       fmt.Sprintf("%s-master-1", name),
				Subnets:        []*abstract.Subnet{mastersubnet},
				DefaultRouteIP: "192.168.0.3",
				TemplateID:     request.MastersDef.Template,
				// TemplateRef
				ImageID: request.MastersDef.Image,
				// ImageRef
				KeyPair:       kp,
				SSHPort:       22,
				Password:      cladmPassword,
				DiskSize:      64,
				Single:        false,
				PublicIP:      false,
				IsGateway:     false,
				KeepOnFailure: false,
				Preemptible:   false,
				SecurityGroupIDs: map[string]struct{}{
					"PublicIPSecurityGroupID": {},
					"GWSecurityGroupID":       {},
					"InternalSecurityGroupID": {},
				},
			})
			if xerr != nil {
				return aci, xerr
			}
		}

		// Cluster node subnet
		if !e._hasInternalData(fmt.Sprintf("subnets/ByID/%s-node-1", name)) {
			_, xerr := e.CreateSubnet(ctx, abstract.SubnetRequest{
				NetworkID:      network.ID,
				Name:           fmt.Sprintf("%s-node-1", name),
				IPVersion:      network.IPVersion,
				CIDR:           network.CIDR,
				DNSServers:     network.DNSServers,
				Domain:         request.Domain,
				HA:             false,
				ImageRef:       "",
				DefaultSSHPort: 22,
				KeepOnFailure:  false,
			})
			if xerr != nil {
				return aci, xerr
			}
			rsubnet, xerr := LoadSubnet(ctx, e, request.NetworkID, fmt.Sprintf("%s-node-1", name))
			if xerr != nil {
				return aci, xerr
			}
			xerr = rsubnet.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				as.GatewayIDs = []string{fmt.Sprintf("gw-%s", name), fmt.Sprintf("gw2-%s", name)}
				return nil
			})
			if xerr != nil {
				return aci, xerr
			}
		}
		nodesubnet, xerr := e.InspectSubnet(ctx, name)
		if xerr != nil {
			return aci, xerr
		}

		// Cluster node
		if !e._hasInternalData(fmt.Sprintf("hosts/ByID/%s-node-1", name)) {
			_, _, xerr = e.CreateHost(ctx, abstract.HostRequest{
				ResourceName:   fmt.Sprintf("%s-node-1", name),
				HostName:       fmt.Sprintf("%s-node-1", name),
				Subnets:        []*abstract.Subnet{nodesubnet},
				DefaultRouteIP: "192.168.0.4",
				TemplateID:     request.MastersDef.Template,
				// TemplateRef
				ImageID: request.MastersDef.Image,
				// ImageRef
				KeyPair:       kp,
				SSHPort:       22,
				Password:      cladmPassword,
				DiskSize:      64,
				Single:        true,
				PublicIP:      false,
				IsGateway:     false,
				KeepOnFailure: false,
				Preemptible:   false,
				SecurityGroupIDs: map[string]struct{}{
					"PublicIPSecurityGroupID": {},
					"GWSecurityGroupID":       {},
					"InternalSecurityGroupID": {},
				},
			})
			if xerr != nil {
				return aci, xerr
			}
		}

		// Cluster
		if !e._hasInternalData(fmt.Sprintf("clusters/%s", name)) {
			e._setInternalData(fmt.Sprintf("clusters/%s", name), aci)
		}

		// Props
		cluster, xerr := LoadCluster(ctx, e, name)
		if xerr != nil {
			return aci, xerr
		}
		ocluster, ok := cluster.(*Cluster)
		if !ok {
			return aci, fail.ConvertError(errors.New("resource.Cluster not castable to operation.Cluster"))
		}
		xerr = ocluster.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			xerr = props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {

				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}
				networkV3.NetworkID = request.NetworkID
				networkV3.CreatedNetwork = true
				networkV3.SubnetID = name
				networkV3.CIDR = request.CIDR
				networkV3.GatewayID = fmt.Sprintf("gw-%s", name)
				networkV3.GatewayIP = "192.168.0.1"
				networkV3.SecondaryGatewayID = fmt.Sprintf("gw2-%s", name)
				networkV3.SecondaryGatewayIP = "192.168.0.2"
				networkV3.DefaultRouteIP = "192.168.0.1"
				networkV3.PrimaryPublicIP = "192.168.0.1"
				networkV3.SecondaryPublicIP = "192.168.0.2"
				networkV3.EndpointIP = "192.168.0.1"
				networkV3.SubnetState = subnetstate.Ready
				networkV3.Domain = request.Domain

				return nil
			})
			if xerr != nil {
				return xerr
			}

			xerr = props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				stateV1.State = clusterstate.Nominal
				return nil
			})
			if xerr != nil {
				return xerr
			}

			innerXErr := props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}
				nodesV3.ByNumericalID = map[uint]*propertiesv3.ClusterNode{
					0: {
						ID:          fmt.Sprintf("gw-%s", name),
						NumericalID: 0,
						Name:        fmt.Sprintf("gw-%s", name),
						PublicIP:    "192.168.0.1",
						PrivateIP:   "192.168.0.1",
					},
					1: {
						ID:          fmt.Sprintf("gw2-%s", name),
						NumericalID: 0,
						Name:        fmt.Sprintf("gw2-%s", name),
						PublicIP:    "192.168.0.2",
						PrivateIP:   "192.168.0.2",
					},
					2: {
						ID:          fmt.Sprintf("%s-master-1", name),
						NumericalID: 0,
						Name:        fmt.Sprintf("%s-master-1", name),
						PublicIP:    "192.168.0.3",
						PrivateIP:   "192.168.0.3",
					},
					3: {
						ID:          fmt.Sprintf("%s-node-1", name),
						NumericalID: 0,
						Name:        fmt.Sprintf("%s-node-1", name),
						PublicIP:    "192.168.0.4",
						PrivateIP:   "192.168.0.4",
					},
				}
				nodesV3.PrivateNodeByID = map[string]uint{
					fmt.Sprintf("gw-%s", name):       0,
					fmt.Sprintf("gw2-%s", name):      1,
					fmt.Sprintf("%s-master-1", name): 2,
					fmt.Sprintf("%s-node-1", name):   3,
				}
				nodesV3.Masters = []uint{2}
				nodesV3.PrivateNodes = []uint{3}

				return nil
			})
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to get list of hosts")
			}

			return nil
		})

	} else {

		// Create Cluster
		cluster, xerr := NewCluster(ctx, e)
		if xerr != nil {
			return aci, xerr
		}
		xerr = cluster.Create(ctx, request)
		if xerr != nil {
			return aci, xerr
		}

	}

	return aci, xerr

}

/* Volume */

func (e *ServiceTest) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	e._survey("ServiceTest::CreateVolume (not implemented)")
	return nil, nil
}
func (e *ServiceTest) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	e._survey("ServiceTest::InspectVolume (not implemented)")
	return nil, nil
}
func (e *ServiceTest) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	e._survey("ServiceTest::ListVolumes (not implemented)")
	return make([]*abstract.Volume, 0), nil
}
func (e *ServiceTest) DeleteVolume(ctx context.Context, id string) fail.Error {
	e._survey("ServiceTest::DeleteVolume (not implemented)")
	return nil
}
func (e *ServiceTest) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	e._survey("ServiceTest::CreateVolumeAttachment (not implemented)")
	return "", nil
}
func (e *ServiceTest) InspectVolumeAttachment(ctx context.Context, serverID string, id string) (*abstract.VolumeAttachment, fail.Error) {
	e._survey("ServiceTest::InspectVolumeAttachment (not implemented)")
	return nil, nil
}
func (e *ServiceTest) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	e._survey("ServiceTest::ListVolumeAttachments (not implemented)")
	return make([]*abstract.VolumeAttachment, 0), nil
}
func (e *ServiceTest) DeleteVolumeAttachment(ctx context.Context, serverID, id string) fail.Error {
	e._survey("ServiceTest::DeleteVolumeAttachment (not implemented)")
	return nil
}
func (e *ServiceTest) Migrate(ctx context.Context, operation string, params map[string]interface{}) fail.Error {
	e._log("ServiceTest::Migrate (not implemented)")
	return nil
}
func (e *ServiceTest) Timings() (temporal.Timings, fail.Error) {
	if e.options.timingsErr != nil {
		e._warnf("ServiceTest::Timings forced error \"%s\"\n", e.options.timingsErr.Error())
		return nil, e.options.timingsErr
	}
	return e.options.timings, nil
}

// providers.Provider
func (e *ServiceTest) Build(map[string]interface{}) (providers.Provider, fail.Error) {
	return providers.Remediator{Name: "ServiceTest"}, nil
}
func (e *ServiceTest) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	e._survey("ServiceTest::ListImages (not implemented)")
	return make([]*abstract.Image, 0), nil
}
func (e *ServiceTest) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	e._survey("ServiceTest::ListTemplates (not implemented)")
	return make([]*abstract.HostTemplate, 0), nil
}
func (e *ServiceTest) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	e._survey("ServiceTest::GetAuthenticationOptions (not implemented)")
	return providers.ConfigMap{}, nil
}
func (e *ServiceTest) GetOperatorUsername(ctx context.Context) (string, fail.Error) {
	if e.options.operatorusernameErr != nil {
		e._warn("ServiceTest::GetOperatorUsername (forced error)")
		return "", e.options.operatorusernameErr
	}
	e._logf("ServiceTest::GetOperatorUsername { value: \"%s\" } ", e.options.operatorusername)
	return e.options.operatorusername, nil
}
func (e *ServiceTest) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
	e._log("ServiceTest::GetConfigurationOptions")

	if valid.IsNil(e) {
		return nil, fail.InvalidInstanceError()
	}
	cfg := providers.ConfigMap{}
	if valid.IsNil(e) {
		return cfg, fail.InvalidInstanceError()
	}
	provName, xerr := e.GetName()
	if xerr != nil {
		return nil, xerr
	}
	operatorusername, xerr := e.GetOperatorUsername(ctx)
	if xerr != nil {
		return nil, xerr
	}
	cfg.Set("DNSList", []string{"8.8.8.8", "4.4.4.4"})
	cfg.Set("AutoHostNetworkInterfaces", false)
	cfg.Set("UseLayer3Networking", false)
	cfg.Set("DefaultImage", "Servicetest-DefaultImage")
	cfg.Set("MetadataBucketName", "Servicetest-MetadataBucketName")
	cfg.Set("OperatorUsername", operatorusername)
	cfg.Set("ProviderName", provName)
	cfg.Set("UseNATService", false)
	cfg.Set("MaxLifeTimeInHours", 1)
	return cfg, nil
}

func (e *ServiceTest) GetName() (string, fail.Error) {
	if e.options.nameErr != nil {
		e._warnf("ServiceTest::GetName forced error \"%s\"\n", e.options.nameErr.Error())
		return "", e.options.nameErr
	}
	return e.options.name, nil
}
func (e *ServiceTest) GetStack() (stacks.Stack, fail.Error) {
	if e.options.stacknameErr != nil {
		e._warnf("ServiceTest::GetStack forced error \"%s\"\n", e.options.stacknameErr.Error())
		return stacks.Remediator{}, e.options.stacknameErr
	}
	return stacks.Remediator{Name: e.options.stackname}, nil
}
func (e *ServiceTest) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	e._survey("ServiceTest::GetRegexpsOfTemplatesWithGPU (not implemented)")
	return []*regexp.Regexp{}, nil
}
func (e *ServiceTest) GetCapabilities(ctx context.Context) (providers.Capabilities, fail.Error) {
	e._logf("ServiceTest::GetCapabilities { PublicVirtualIP: false, PrivateVirtualIP: false, Layer3Networking: false, CanDisableSecurityGroup: %t }", e.options.candisablesecuritygroup)
	return providers.Capabilities{
		PublicVirtualIP:         false,
		PrivateVirtualIP:        false,
		Layer3Networking:        false,
		CanDisableSecurityGroup: e.options.candisablesecuritygroup,
	}, nil
}
func (e *ServiceTest) GetTenantParameters() (map[string]interface{}, fail.Error) {
	e._survey("ServiceTest::GetTenantParameters (not implemented)")
	return map[string]interface{}{}, nil
}

// objectstorage.Location
func (e *ServiceTest) Protocol() (string, fail.Error) {
	if e.options.protocolErr != nil {
		e._logf("ServiceTest::Protocol forced error \"%s\"\n", e.options.protocolErr.Error())
		return "", e.options.protocolErr
	}
	return e.options.protocol, nil
}
func (e *ServiceTest) Configuration() (objectstorage.Config, fail.Error) {
	e._survey("ServiceTest::Configuration (not implemented)")
	return objectstorage.Config{}, nil
}
func (e *ServiceTest) ListBuckets(context.Context, string) ([]string, fail.Error) {
	e._survey("ServiceTest::ListBuckets (not implemented)")
	return []string{}, nil
}
func (e *ServiceTest) FindBucket(ctx context.Context, name string) (bool, fail.Error) {
	e._logf("ServiceTest::FindBucket { name: \"%s\"}", name)
	e.internals.bucketData.mu.Lock()
	_, ok := e.internals.bucketData.data[fmt.Sprintf("buckets/byID/%s", name)]
	if !ok {
		_, ok = e.internals.bucketData.data[fmt.Sprintf("buckets/byName/%s", name)]
	}
	e.internals.bucketData.mu.Unlock()
	return ok, nil
}
func (e *ServiceTest) InspectBucket(ctx context.Context, name string) (abstract.ObjectStorageBucket, fail.Error) {
	e._surveyf("ServiceTest::InspectBucket { name: \"%s\"} (not implemented)", name)
	return abstract.ObjectStorageBucket{}, nil
}
func (e *ServiceTest) CreateBucket(ctx context.Context, name string) (abstract.ObjectStorageBucket, fail.Error) {
	e._logf("ServiceTest::CreateBucket { name: \"%s\"}", name)
	b := abstract.ObjectStorageBucket{
		ID:         name,
		Name:       name,
		Host:       "localhost",
		MountPoint: e.internals.tmpdir,
	}

	// Pre-save bucket
	err := e._setInternalData(fmt.Sprintf("buckets/byID/%s", name), &b)
	if err != nil {
		return b, fail.Wrap(err)
	}
	err = e._setInternalData(fmt.Sprintf("buckets/byName/%s", name), &b)
	if err != nil {
		return b, fail.Wrap(err)
	}

	/*
		 bucket, xerr := NewCore(e, "bucket", "buckets", &b)
		 if xerr != nil {
			 return b, xerr
		 }
		 xerr = bucket.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			 return props.Alter(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
				 mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
				 if !ok {
					 return fail.InconsistentError("'*propertiesv1.BucketMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				 }
				 mountsV1.ByHostID
				 mountsV1.ByHostName
				 return nil
			 })

			 return nil
		 })
		 if xerr != nil {
			 return b, xerr
		 }
	*/

	return b, nil
}
func (e *ServiceTest) DeleteBucket(ctx context.Context, name string) fail.Error {
	e._logf("ServiceTest::DeleteBucket { name: \"%s\"}\n", name)
	err := e._deleteInternalData(fmt.Sprintf("buckets/byID/%s", name))
	if err != nil {
		return fail.Wrap(err)
	}
	err = e._deleteInternalData(fmt.Sprintf("buckets/byName/%s", name))
	if err != nil {
		return fail.Wrap(err)
	}
	return nil
}
func (e *ServiceTest) ClearBucket(ctx context.Context, bucketname string, path string, prefix string) fail.Error {
	e._logf("ServiceTest::ClearBucket { bucketname: \"%s\", path: \"%s\", prefix: \"%s\"}\n", bucketname, path, prefix)
	return nil
}
func (e *ServiceTest) ListObjects(ctx context.Context, bucketname string, path string, prefix string) ([]string, fail.Error) {
	if e.options.listobjectsErr != nil {
		e._logf("ServiceTest::ListObjects { bucketname: \"%s\", path: \"%s\", prefix: \"%s\"} forced error \"%s\"\n", bucketname, path, prefix, e.options.listobjectsErr.Error())
		return []string{}, e.options.listobjectsErr
	}
	keys := e._getInternalDataKeys(path)
	if len(keys) > 0 {
		e._logf("ServiceTest::ListObjects { bucketname: \"%s\", path: \"%s\", prefix: \"%s\", results: {\"%s\"}}\n", bucketname, path, prefix, strings.Join(keys, "\",\""))
	} else {
		e._logf("ServiceTest::ListObjects { bucketname: \"%s\", path: \"%s\", prefix: \"%s\", results: <no_results>}\n", bucketname, path, prefix)
	}
	return keys, nil
}

func (e *ServiceTest) InspectObject(ctx context.Context, bucketname string, path string) (abstract.ObjectStorageItem, fail.Error) {

	osi := abstract.ObjectStorageItem{
		BucketName: "bucketname",
		ItemID:     "id",
		ItemName:   "name",
		Metadata:   abstract.ObjectStorageItemMetadata{},
	}
	e._logf("ServiceTest::InspectObject { bucketname: \"%s\", path: \"%s\"}\n", bucketname, path)
	return osi, nil
}

func (e *ServiceTest) InvalidateObject(ctx context.Context, bucketname string, path string) fail.Error {
	e._surveyf("ServiceTest::InvalidateObject { bucketname: \"%s\", path: \"%s\"} (not implemented)\n", bucketname, path)
	return nil
}

func (e *ServiceTest) HasObject(ctx context.Context, bucketname string, path string) (has bool, ferr fail.Error) {
	has = e._hasInternalData(path)
	if has {
		e._logf("ServiceTest::HasObject { bucketname: \"%s\", path: \"%s\", has: %t}\n", bucketname, path, has)
	} else {
		e._warnf("ServiceTest::HasObject { bucketname: \"%s\", path: \"%s\", has: %t}\n", bucketname, path, has)
	}
	return has, nil
}
func (e *ServiceTest) ReadObject(ctx context.Context, bucketname string, path string, buffer io.Writer, offset int64, length int64) (ferr fail.Error) { // nolint

	defer fail.OnPanic(&ferr)

	switch path {
	case "version":
		e._logf("ServiceTest::ReadObject { bucketname: \"%s\", path: \"%s\", value: \"%s\"}\n", bucketname, path, e.options.version)
		if e.options.versionErr != nil {
			return e.options.versionErr
		}
		_, err := buffer.Write([]byte(e.options.version))
		if err != nil {
			return fail.Wrap(err)
		}
		length = int64(len(e.options.version)) // nolint
	default:

		val, err := e._getRawInternalData(path)
		if err == nil {
			dataValue := "[Serial]"
			if e.internals.loglevel > 1 {
				dataValue, _ = e._getInternalData(path)
			}
			e._logf("ServiceTest::ReadObject { bucketname: \"%s\", path: \"%s\", value: %s }\n", bucketname, path, dataValue)
			_, err := buffer.Write([]byte(val))
			if err != nil {
				return fail.Wrap(err)
			}
			length = int64(len(val)) // nolint
		} else {
			e._warnf("ServiceTest::ReadObject { bucketname: \"%s\", path: \"%s\", value: ?} not found !\n", bucketname, path)
			return fail.NotFoundError("path \"" + path + "\" not found")
		}
	}
	return nil
}
func (e *ServiceTest) WriteMultiPartObject(context.Context, string, string, io.Reader, int64, int, abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	e._warnf("ServiceTest::WriteObject (not implemented)")
	return abstract.ObjectStorageItem{}, nil
}
func (e *ServiceTest) WriteObject(ctx context.Context, bucketname string, path string, buffer io.Reader, length int64, item abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	tmp := make([]byte, length)
	if _, err := io.ReadFull(buffer, tmp); err != nil {
		e._warnf("ServiceTest::WriteObject { bucketname: \"%s\", path: \"%s\", value: ? } error: %s\n", bucketname, path, err.Error())
		return abstract.ObjectStorageItem{}, fail.NewError(err)
	}
	dataValue := "[Serial]"
	if e.internals.loglevel > 1 {
		dataValue, _ = e._decodeItem(string(tmp))
	}
	e._logf("ServiceTest::WriteObject { bucketname: \"%s\", path: \"%s\", value: \"%s\"}\n", bucketname, path, dataValue)
	e.internals.bucketData.mu.Lock()
	e.internals.bucketData.data[path] = string(tmp)
	e.internals.bucketData.mu.Unlock()
	return abstract.ObjectStorageItem{}, nil
}
func (e *ServiceTest) DeleteObject(ctx context.Context, bucketname string, path string) fail.Error {

	if e._hasInternalData(path) {
		e._logf("ServiceTest::DeleteObject { bucketname: \"%s\", path: \"%s\"}", bucketname, path)
	} else {
		e._warnf("ServiceTest::DeleteObject { bucketname: \"%s\", path: \"%s\"} not found", bucketname, path)
	}
	err := e._deleteInternalData(path)
	if err != nil {
		return fail.NotFoundError(fmt.Sprintf("path \"%s\" not found", path))
	}
	return nil
}

// extra
func (e *ServiceTest) GetMetadataKey() (*crypt.Key, fail.Error) {
	if e.options.metadatakeyErr != nil {
		e._warnf("ServiceTest::GetMetadataKey forced error \"%s\"", e.options.metadatakeyErr.Error())
		return nil, e.options.metadatakeyErr
	}
	key, err := crypt.NewEncryptionKey([]byte(e.options.metadatakey))
	if err == nil {
		return key, nil
	}
	return nil, fail.Wrap(err)
}

// ------------------------------------------------------------------------------------------------------
/*
type CacheTest struct {
	name  string
	svc   *ServiceTest
	cache map[string]*cache.Entry // nolint
}

func NewCacheTest(name string, svc *ServiceTest) *CacheTest {
	return &CacheTest{
		name: name,
		svc:  svc,
	}
}
func (e *CacheTest) Get(ctx context.Context, key string, options ...data.ImmutableKeyValue) (ce *cache.Entry, xerr fail.Error) {
	e.svc._logf("CacheTest::Get { key: \"%s\" }", key)
	return e.svc._cache_Get(ctx, e.name, key, options...)
}
func (e *CacheTest) ReserveEntry(ctx context.Context, key string, timeout time.Duration) fail.Error {
	e.svc._logf("CacheTest::ReserveEntry { key: \"%s\" }", key)
	return e.svc._cache_ReserveEntry(ctx, e.name, key, timeout)
}
func (e *CacheTest) CommitEntry(ctx context.Context, key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	e.svc._logf("CacheTest::CommitEntry { key: \"%s\" }", key)
	return e.svc._cache_CommitEntry(ctx, e.name, key, content)
}
func (e *CacheTest) FreeEntry(ctx context.Context, key string) fail.Error {
	e.svc._logf("CacheTest::FreeEntry { key: \"%s\" }", key)
	return e.svc._cache_FreeEntry(ctx, e.name, key)

}
func (e *CacheTest) AddEntry(ctx context.Context, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	e.svc._logf("CacheTest::AddEntry")
	return e.svc._cache_AddEntry(ctx, e.name, content)
}
*/
// ------------------------------------------------------------------------------------------------------

type SSHConnectorTest struct {
	sshapi.Connector
	svc    *ServiceTest
	config sshapi.Config
}

var (
	currentSVCSSHConnectorTest *ServiceTest = nil
)

func SSHConnectorTest_Overload(svc *ServiceTest, routine func(svc *ServiceTest)) {
	currentSVCSSHConnectorTest = svc
	sshfactory.SetCustomConnectorFactory(SSHConnectorTestFactory) // nolint
	routine(currentSVCSSHConnectorTest)
	sshfactory.SetCustomConnectorFactory(nil)
}

func SSHConnectorTestFactory(config sshapi.Config) (sshapi.Connector, fail.Error) {
	conn := &SSHConnectorTest{
		svc:    currentSVCSSHConnectorTest,
		config: config,
	}
	return conn, nil
}

func (e *SSHConnectorTest) Config() (sshapi.Config, fail.Error) {
	e.svc._survey("SSHConnectorTest::Config")
	return e.config, nil
}
func (e *SSHConnectorTest) CopyWithTimeout(ctx context.Context, remotePath string, localPath string, isUpload bool, delay time.Duration) (retcode int, stdout string, stderr string, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	e.svc._surveyf("SSHConnectorTest::CopyWithTimeout { local: %s, remote: %s, upload: %t} remote} (emulated)", localPath, remotePath, isUpload)

	if valid.IsNil(e) {
		return -1, "", "", fail.InvalidInstanceError()
	}
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return -1, "", "", xerr
	}
	if task.Aborted() {
		return -1, "", "", fail.AbortedError(nil, "aborted")
	}
	if isUpload {
		b, err := ioutil.ReadFile(localPath)
		if err != nil {
			return -1, "", "", fail.Wrap(err)
		}
		xerr := e.svc._setFsCache(remotePath, b)
		if xerr != nil {
			return -1, "", "", xerr
		}
	} else {
		b, xerr := e.svc._getFsCache(remotePath)
		if xerr != nil {
			return 1, "", fmt.Sprintf("file \"%s\"not found", remotePath), xerr
		}
		err := os.WriteFile(localPath, b, 0644)
		if err != nil {
			return 1, "", "", fail.Wrap(err)
		}
	}
	retcode = 0
	stdout = ""
	stderr = ""
	return retcode, stdout, stderr, nil
}
func (e *SSHConnectorTest) Close() fail.Error {
	e.svc._survey("SSHConnectorTest::Close (not implemented)")
	return nil
}
func (e *SSHConnectorTest) CreatePersistentTunnel() fail.Error {
	e.svc._survey("SSHConnectorTest::CreatePersistentTunnel (not implemented)")
	return nil
}
func (e *SSHConnectorTest) Enter(ctx2 context.Context, username string, shell string) (ferr fail.Error) {
	e.svc._surveyf("SSHConnectorTest::Enter { user: \"%s\", shell: \"%s\" }", username, shell)

	defer fail.OnPanic(&ferr)

	ctx := context.Background()

	if valid.IsNull(e) {
		return fail.InvalidInstanceError()
	}
	cmd, xerr := e.NewCommand(ctx, shell)
	if xerr != nil {
		return xerr
	}
	_, _, _, xerr = cmd.RunWithTimeout(ctx, outputs.COLLECT, 30*time.Second) // nolint
	return xerr
}
func (e *SSHConnectorTest) NewCommand(ctx context.Context, cmdString string) (sshapi.Command, fail.Error) {
	e.svc._logf("SSHConnectorTest::NewCommand { cmd: \"%s\"} (emulated)", e.svc._cramp(cmdString, 64))

	hostname, xerr := e.config.GetHostname()
	if xerr != nil {
		return nil, xerr
	}
	cmd := &SSHCommandTest{
		svc:          e.svc,
		hostname:     hostname,
		runCmdString: cmdString,
		output:       "",
	}
	return cmd, nil
}
func (e *SSHConnectorTest) NewSudoCommand(ctx context.Context, cmdString string) (sshapi.Command, fail.Error) {
	e.svc._logf("SSHConnectorTest::NewSudoCommand { cmd: \"%s\"} (emulated)", e.svc._cramp(cmdString, 64))
	return e.NewCommand(ctx, "sudo "+cmdString)
}
func (e *SSHConnectorTest) WaitServerReady(ctx context.Context, phase string, delay time.Duration) (stdout string, ferr fail.Error) {

	defer fail.OnPanic(&ferr)

	e.svc._surveyf("SSHConnectorTest::WaitServerReady { phase: \"%s\"} (emulated)", phase)

	if e == nil {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if phase == "" {
		return "", fail.InvalidParameterError("phase", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	originalPhase := phase
	if phase == "ready" {
		phase = "final"
	}

	stdout = "23:59:59 up 0 days, 23:59, 1 user, load average: 0,99"

	hostname, xerr := e.config.GetHostname()
	if xerr != nil {
		hostname = "<???>"
	}
	logrus.Debugf("[emulated] sudo cat %s/state/user_data.%s.done", utils.VarFolder, phase)
	logrus.Debugf("host [%s] phase [%s] check successful in [%s]: host stdout is [%s]", hostname, originalPhase, temporal.FormatDuration(0), stdout)

	return stdout, nil

}

// ------------------------------------------------------------------------------------------------------

type SSHCommandTest struct {
	sshapi.Command
	svc          *ServiceTest
	hostname     string
	runCmdString string
	output       string
}

func (e *SSHCommandTest) Output() (data []byte, xerr fail.Error) {
	e.svc._logf("SSHCommandTest::Output { output: \"%s\" }", e.svc._cramp(e.output, 64))
	return []byte(e.output), nil
}
func (e *SSHCommandTest) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (retcode int, stdout string, stderr string, xerr fail.Error) {
	if e.output == "" {
		e.output = e.svc._sshCommand(e.runCmdString)
	}
	e.svc._logf("SSHCommandTest::RunWithTimeout { hostname: \"%s\", cmd: \"%s\", output: \"%s\" }", e.hostname, e.svc._cramp(e.runCmdString, 64), e.svc._cramp(e.output, 64))
	return 0, e.output, "", nil
}

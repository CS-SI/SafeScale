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

package handlers

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/graymeta/stow"
	"github.com/savaki/jq"
	"github.com/sirupsen/logrus"

	clumeta "github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List(context.Context) ([]string, error)
	Create(context.Context, string) error
	Delete(context.Context, string) error
	Prune(context.Context, string) error
	Destroy(context.Context, string) error
	Inspect(context.Context, string) (*abstract.Bucket, error)
	Verify(context.Context, string) ([]error, error)
	Mount(context.Context, string, string, string) error
	Unmount(context.Context, string, string) error
}

// BucketHandler bucket service
type BucketHandler struct {
	service iaas.Service
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(svc iaas.Service) BucketAPI {
	return &BucketHandler{service: svc}
}

// List retrieves all available buckets
func (handler *BucketHandler) List(ctx context.Context) (rv []string, err error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	rv, err = handler.service.ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *BucketHandler) Create(ctx context.Context, name string) (err error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	bucket, err := handler.service.GetBucket(name)
	if err != nil {
		if !isErrorNotFound(err) { // FIXME: Remove stow dependency
			return err
		}
	}
	if bucket != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	_, err = handler.service.CreateBucket(name)
	return err
}

func isErrorNotFound(in error) bool {
	if in == nil {
		return false
	}

	if in == stow.ErrNotFound {
		return true
	}

	if _, ok := in.(fail.ErrNotFound); ok {
		return true
	}

	return false
}

// Destroy a bucket, clear then delete
func (handler *BucketHandler) Destroy(ctx context.Context, name string) (err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.service.ClearBucket(name, "/", "")
	if err != nil {
		return err
	}

	err = handler.service.DeleteBucket(name)
	return err
}

// Delete a bucket
func (handler *BucketHandler) Delete(ctx context.Context, name string) (err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.service.DeleteBucket(name)
	return err
}

// getMD5Hash returns the MD5 of the string 'text'
func getMD5Hash(text string) (_ string, err error) {
	hasher := md5.New()
	_, err = hasher.Write([]byte(text))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Prune a bucket
func (handler *BucketHandler) Prune(ctx context.Context, name string) (err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	bu, err := handler.service.GetBucket(name)
	if err != nil {
		if isErrorNotFound(err) {
			return abstract.ResourceNotFoundError("bucket", name)
		}

		return err
	}

	buname, err := bu.GetName()
	if err != nil {
		return err
	}
	logrus.Debugf("Verifying bucket %s", buname)

	contents, err := bu.List("", "")
	if err != nil {
		return err
	}

	contentsCopy, err := bu.List("", "")
	if err != nil {
		return err
	}

	crik := handler.service.GetMetadataKey()

	var machines []string
	var nets []string
	var vols []string

	type hostInfo struct {
		Id   string
		Name string
	}

	for _, ct := range contents {
		if strings.Contains(ct, metadata.HostsFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				machineId := fragments[len(fragments)-1]

				// If the host actually exists, go to next host
				_, err = handler.service.InspectHost(machineId)
				if err != nil {
					machines = append(machines, machineId)
				} else {
					continue
				}

				// Let's recover and decrypt...
				var buffer bytes.Buffer
				_, err = bu.ReadObject(ct, &buffer, 0, 0)
				if err != nil {
					return err
				}

				data := buffer.Bytes()
				data, err = crypt.Decrypt(data, crik)
				if err != nil {
					return err
				}

				hin := hostInfo{}
				err = json.Unmarshal(data, &hin)
				if err != nil {
					return err
				}

				warPath := strings.Join([]string{metadata.HostsFolderName, metadata.ByNameFolderName, hin.Name}, "/")
				var otherBuffer bytes.Buffer
				_, err = bu.ReadObject(warPath, &otherBuffer, 0, 0)
				if err != nil {
					return err
				}

				foundPair := false
				for _, candidate := range contentsCopy {
					if warPath == candidate {
						foundPair = true
						break
					}
				}

				if foundPair {
					odata := otherBuffer.Bytes()
					odata, err = crypt.Decrypt(odata, crik)
					if err != nil {
						return err
					}

					ra, err := getMD5Hash(string(data))
					if err != nil {
						return err
					}
					rb, err := getMD5Hash(string(odata))
					if err != nil {
						return err
					}
					if strings.Compare(ra, rb) == 0 {
						err = bu.DeleteObject(ct)
						if err != nil {
							continue
						}
						err = bu.DeleteObject(warPath)
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	for _, ct := range contents {
		if strings.Contains(ct, metadata.NetworksFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				netId := fragments[len(fragments)-1]
				_, err = handler.service.GetNetwork(netId)
				if err != nil {
					nets = append(nets, netId)
				} else {
					continue
				}

				// Let's recover and decrypt...
				var buffer bytes.Buffer
				_, err = bu.ReadObject(ct, &buffer, 0, 0)
				if err != nil {
					return err
				}

				data := buffer.Bytes()
				data, err = crypt.Decrypt(data, crik)
				if err != nil {
					return err
				}

				hin := hostInfo{}
				err = json.Unmarshal(data, &hin)
				if err != nil {
					return err
				}

				warPath := strings.Join([]string{metadata.NetworksFolderName, metadata.ByNameFolderName, hin.Name}, "/")
				var otherBuffer bytes.Buffer
				_, err = bu.ReadObject(warPath, &otherBuffer, 0, 0)
				if err != nil {
					return err
				}

				foundPair := false
				for _, candidate := range contentsCopy {
					if warPath == candidate {
						foundPair = true
						break
					}
				}

				if foundPair {
					odata := otherBuffer.Bytes()
					odata, err = crypt.Decrypt(odata, crik)
					if err != nil {
						return err
					}

					ra, err := getMD5Hash(string(data))
					if err != nil {
						return err
					}
					rb, err := getMD5Hash(string(odata))
					if err != nil {
						return err
					}
					if strings.Compare(ra, rb) == 0 {
						err = bu.DeleteObject(ct)
						if err != nil {
							continue
						}
						err = bu.DeleteObject(warPath)
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	for _, ct := range contents {
		if strings.Contains(ct, metadata.VolumesFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				volId := fragments[len(fragments)-1]
				_, err = handler.service.GetVolume(volId)
				if err != nil {
					logrus.Debugf("Volume no longer there %s", volId)
					vols = append(vols, volId)
				} else {
					continue
				}

				// Let's recover and decrypt...
				var buffer bytes.Buffer
				_, err = bu.ReadObject(ct, &buffer, 0, 0)
				if err != nil {
					return err
				}

				data := buffer.Bytes()
				data, err = crypt.Decrypt(data, crik)
				if err != nil {
					return err
				}

				hin := hostInfo{}
				err = json.Unmarshal(data, &hin)
				if err != nil {
					return err
				}

				warPath := strings.Join([]string{metadata.VolumesFolderName, metadata.ByNameFolderName, hin.Name}, "/")
				var otherBuffer bytes.Buffer
				_, err = bu.ReadObject(warPath, &otherBuffer, 0, 0)
				if err != nil {
					return err
				}

				foundPair := false
				for _, candidate := range contentsCopy {
					if warPath == candidate {
						foundPair = true
						break
					}
				}

				if foundPair {
					odata := otherBuffer.Bytes()
					odata, err = crypt.Decrypt(odata, crik)
					if err != nil {
						return err
					}

					ra, err := getMD5Hash(string(data))
					if err != nil {
						return err
					}
					rb, err := getMD5Hash(string(odata))
					if err != nil {
						return err
					}
					if strings.Compare(ra, rb) == 0 {
						err = bu.DeleteObject(ct)
						if err != nil {
							continue
						}
						err = bu.DeleteObject(warPath)
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	for _, ct := range contents {
		if strings.Contains(ct, clumeta.ClusterFolderName) {
			var otherBuffer bytes.Buffer
			_, err = bu.ReadObject(ct, &otherBuffer, 0, 0)
			if err != nil {
				return err
			}

			odata := otherBuffer.Bytes()
			odata, err = crypt.Decrypt(odata, crik)
			if err != nil {
				return err
			}

			gop, _ := jq.Parse(".properties.10")
			gvalue, _ := gop.Apply(odata)
			cleaned := strings.ReplaceAll(string(gvalue), `\"`, `"`)
			if len(cleaned) > 1 {
				cleaned = cleaned[1 : len(cleaned)-1]
			}

			gate, _ := jq.Parse(".gateway_id")
			_, _ = gate.Apply([]byte(cleaned))

			gate, _ = jq.Parse(".secondary_gateway_id")
			_, _ = gate.Apply([]byte(cleaned))

			op, _ := jq.Parse(".properties.6")
			value, _ := op.Apply(odata)
			cleaned = strings.ReplaceAll(string(value), `\"`, `"`)
			if len(cleaned) > 1 {
				cleaned = cleaned[1 : len(cleaned)-1]
			}

			// get masters
			var masterIds []string
			ind := 0

			for {
				masterPattern, _ := jq.Parse(fmt.Sprintf(".masters.[%d].id", ind))
				masterCapture, err := masterPattern.Apply([]byte(cleaned))
				if err != nil {
					break
				}
				masterIds = append(masterIds, string(masterCapture))
				ind++
			}

			// little
			var privateNodesIds []string
			ind = 0

			for {
				privPattern, _ := jq.Parse(fmt.Sprintf(".private_nodes.[%d].id", ind))
				privCaptured, err := privPattern.Apply([]byte(cleaned))
				if err != nil {
					break
				}
				privateNodesIds = append(privateNodesIds, string(privCaptured))
				ind++
			}

			// public nodes
			var publicNodesIds []string
			ind = 0

			for {
				pubPattern, _ := jq.Parse(fmt.Sprintf(".public_nodes.[%d].id", ind))
				pubCaptured, err := pubPattern.Apply([]byte(cleaned))
				if err != nil {
					break
				}
				publicNodesIds = append(publicNodesIds, string(pubCaptured))
				ind++
			}

			resoucesNotClaned := 0

			for _, each := range masterIds {
				if _, err := handler.service.GetHostByID(each); err != nil {
					logrus.Debugf("Host with id %s no longer there", each)
				} else {
					resoucesNotClaned++
				}
			}
			for _, each := range privateNodesIds {
				if _, err := handler.service.GetHostByID(each); err != nil {
					logrus.Debugf("Host with id %s no longer there", each)
				} else {
					resoucesNotClaned++
				}
			}
			for _, each := range publicNodesIds {
				if _, err := handler.service.GetHostByID(each); err != nil {
					logrus.Debugf("Host with id %s no longer there", each)
				} else {
					resoucesNotClaned++
				}
			}

			if resoucesNotClaned == 0 {
				derr := bu.DeleteObject(ct)
				if derr != nil {
					logrus.Debugf("Problem cleaning cluster metadata: %v", derr)
				}
			}
		}
	}

	return nil
}

func (handler *BucketHandler) Verify(ctx context.Context, name string) (errs []error, err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	bu, err := handler.service.GetBucket(name)
	if err != nil {
		if isErrorNotFound(err) {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}

		return nil, err
	}

	buname, err := bu.GetName()
	if err != nil {
		return nil, err
	}
	logrus.Debugf("Verifying bucket %s", buname)

	contents, err := bu.List("", "")
	if err != nil {
		return nil, err
	}

	for _, ct := range contents {
		if strings.Contains(ct, metadata.HostsFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				machineId := fragments[len(fragments)-1]
				_, err = handler.service.InspectHost(machineId)
				if err != nil {
					errs = append(errs, fmt.Errorf("host not found %s", machineId))
				}
			}
		}

		if strings.Contains(ct, metadata.VolumesFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				volumeId := fragments[len(fragments)-1]
				_, err = handler.service.GetVolume(volumeId)
				if err != nil {
					errs = append(errs, fmt.Errorf("volume not found %s", volumeId))
				}
			}
		}

		if strings.Contains(ct, metadata.NetworksFolderName) {
			if strings.Contains(ct, metadata.ByIDFolderName) {
				fragments := strings.Split(ct, "/")
				networkId := fragments[len(fragments)-1]
				_, err = handler.service.GetNetwork(networkId)
				if err != nil {
					errs = append(errs, fmt.Errorf("network not found %s", networkId))
				}
			}
		}
	}

	return errs, nil
}

// Inspect a bucket
func (handler *BucketHandler) Inspect(ctx context.Context, name string) (mb *abstract.Bucket, err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	b, err := handler.service.GetBucket(name)
	if err != nil {
		if isErrorNotFound(err) {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}

		return nil, err
	}

	bucketName, err := b.GetName()
	if err != nil {
		return nil, err
	}

	mb = &abstract.Bucket{
		Name: bucketName,
	}
	return mb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *BucketHandler) Mount(ctx context.Context, bucketName, hostName, path string) (err error) {
	tracer := debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, hostName, path), true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.service.GetBucket(bucketName)
	if err != nil {
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := handler.service.GetAuthenticationOptions()
	authurlCfg, _ := authOpts.Config("AuthUrl")
	authurl := authurlCfg.(string)
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenantCfg, _ := authOpts.Config("TenantName")
	tenant := tenantCfg.(string)
	loginCfg, _ := authOpts.Config("Login")
	login := loginCfg.(string)
	passwordCfg, _ := authOpts.Config("Password")
	password := passwordCfg.(string)
	regionCfg, _ := authOpts.Config("Region")
	region := regionCfg.(string)

	objStorageProtocol := handler.service.GetType()
	if objStorageProtocol == "swift" {
		objStorageProtocol = "swiftks"
	}

	data := struct {
		Bucket     string
		Tenant     string
		Login      string
		Password   string
		AuthURL    string
		Region     string
		MountPoint string
		Protocol   string
	}{
		Bucket:     bucketName,
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
		Protocol:   objStorageProtocol,
	}

	rerr := exec(ctx, "mount_object_storage.sh", data, host.ID, handler.service)
	return rerr
}

// Unmount a bucket
func (handler *BucketHandler) Unmount(ctx context.Context, bucketName, hostName string) (err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.Inspect(ctx, bucketName)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return err
		}
		return err
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(ctx, "umount_object_storage.sh", data, host.ID, handler.service)
	return rerr
}

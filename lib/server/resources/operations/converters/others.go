/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package converters

// Contains functions that are used to convert from everything else

import (
	"strings"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/sirupsen/logrus"
)

// BucketListToProtocol convert a list of string into a *ContainerLsit
func BucketListToProtocol(in []string) *protocol.BucketList {
	var buckets []*protocol.Bucket
	for _, name := range in {
		buckets = append(buckets, &protocol.Bucket{Name: name})
	}
	return &protocol.BucketList{
		Buckets: buckets,
	}
}

// NFSExportOptionsFromStringToProtocol converts a string containing NFS export options as string to the (now deprecated) protocol message
func NFSExportOptionsFromStringToProtocol(in string) *protocol.NFSExportOptions {
	parts := strings.Split(in, ",")
	out := &protocol.NFSExportOptions{}
	for _, v := range parts {
		v = strings.ToLower(v)
		switch v {
		case "read_only":
			out.ReadOnly = true
		case "root_squash":
			out.RootSquash = true
		case "no_root_squash":
			out.RootSquash = false
		case "secure":
			out.Secure = true
		case "insecure":
			out.Secure = false
		case "async":
			out.Async = true
		case "sync":
			out.Async = false
		case "nohide":
			out.NoHide = true
		case "crossmnt":
			out.CrossMount = true
		case "subtree_check":
			out.SubtreeCheck = true
		case "no_subtree_check":
			out.SubtreeCheck = false
		default:
			logrus.Warnf("unhandled NFS option '%s', ignoring.", v)
		}
	}
	return out
}

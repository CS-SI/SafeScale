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


// This file was generated by go generate; DO NOT EDIT

// generated at 2018-12-21 00:47:11.090767 +0000 UTC

package aws

// InstanceType is an EC2 instance type.
type InstanceType struct {
    InstanceType string
    VCPU         int64
    MemoryMb     int64
    GPU          int64
    MaxPods      int64
}

// InstanceTypes is a map of EC2 resources.
var InstanceTypes = map[string]*InstanceType{
    "a1": {
        InstanceType: "a1",
        VCPU:         16,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "a1.2xlarge": {
        InstanceType: "a1.2xlarge",
        VCPU:         8,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      0,
    },
    "a1.4xlarge": {
        InstanceType: "a1.4xlarge",
        VCPU:         16,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      0,
    },
    "a1.large": {
        InstanceType: "a1.large",
        VCPU:         2,
        MemoryMb:     4096,
        GPU:          0,
        MaxPods:      0,
    },
    "a1.medium": {
        InstanceType: "a1.medium",
        VCPU:         1,
        MemoryMb:     2048,
        GPU:          0,
        MaxPods:      0,
    },
    "a1.xlarge": {
        InstanceType: "a1.xlarge",
        VCPU:         4,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      0,
    },
    "c1.medium": {
        InstanceType: "c1.medium",
        VCPU:         2,
        MemoryMb:     1740,
        GPU:          0,
        MaxPods:      12,
    },
    "c1.xlarge": {
        InstanceType: "c1.xlarge",
        VCPU:         8,
        MemoryMb:     7168,
        GPU:          0,
        MaxPods:      58,
    },
    "c3": {
        InstanceType: "c3",
        VCPU:         32,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "c3.2xlarge": {
        InstanceType: "c3.2xlarge",
        VCPU:         8,
        MemoryMb:     15360,
        GPU:          0,
        MaxPods:      58,
    },
    "c3.4xlarge": {
        InstanceType: "c3.4xlarge",
        VCPU:         16,
        MemoryMb:     30720,
        GPU:          0,
        MaxPods:      234,
    },
    "c3.8xlarge": {
        InstanceType: "c3.8xlarge",
        VCPU:         32,
        MemoryMb:     61440,
        GPU:          0,
        MaxPods:      234,
    },
    "c3.large": {
        InstanceType: "c3.large",
        VCPU:         2,
        MemoryMb:     3840,
        GPU:          0,
        MaxPods:      29,
    },
    "c3.xlarge": {
        InstanceType: "c3.xlarge",
        VCPU:         4,
        MemoryMb:     7680,
        GPU:          0,
        MaxPods:      58,
    },
    "c4": {
        InstanceType: "c4",
        VCPU:         36,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "c4.2xlarge": {
        InstanceType: "c4.2xlarge",
        VCPU:         8,
        MemoryMb:     15360,
        GPU:          0,
        MaxPods:      58,
    },
    "c4.4xlarge": {
        InstanceType: "c4.4xlarge",
        VCPU:         16,
        MemoryMb:     30720,
        GPU:          0,
        MaxPods:      234,
    },
    "c4.8xlarge": {
        InstanceType: "c4.8xlarge",
        VCPU:         36,
        MemoryMb:     61440,
        GPU:          0,
        MaxPods:      234,
    },
    "c4.large": {
        InstanceType: "c4.large",
        VCPU:         2,
        MemoryMb:     3840,
        GPU:          0,
        MaxPods:      29,
    },
    "c4.xlarge": {
        InstanceType: "c4.xlarge",
        VCPU:         4,
        MemoryMb:     7680,
        GPU:          0,
        MaxPods:      58,
    },
    "c5": {
        InstanceType: "c5",
        VCPU:         72,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "c5.18xlarge": {
        InstanceType: "c5.18xlarge",
        VCPU:         72,
        MemoryMb:     147456,
        GPU:          0,
        MaxPods:      737,
    },
    "c5.2xlarge": {
        InstanceType: "c5.2xlarge",
        VCPU:         8,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "c5.4xlarge": {
        InstanceType: "c5.4xlarge",
        VCPU:         16,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      234,
    },
    "c5.9xlarge": {
        InstanceType: "c5.9xlarge",
        VCPU:         36,
        MemoryMb:     73728,
        GPU:          0,
        MaxPods:      234,
    },
    "c5.large": {
        InstanceType: "c5.large",
        VCPU:         2,
        MemoryMb:     4096,
        GPU:          0,
        MaxPods:      29,
    },
    "c5.xlarge": {
        InstanceType: "c5.xlarge",
        VCPU:         4,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      58,
    },
    "c5d": {
        InstanceType: "c5d",
        VCPU:         72,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "c5d.18xlarge": {
        InstanceType: "c5d.18xlarge",
        VCPU:         72,
        MemoryMb:     147456,
        GPU:          0,
        MaxPods:      737,
    },
    "c5d.2xlarge": {
        InstanceType: "c5d.2xlarge",
        VCPU:         8,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "c5d.4xlarge": {
        InstanceType: "c5d.4xlarge",
        VCPU:         16,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      234,
    },
    "c5d.9xlarge": {
        InstanceType: "c5d.9xlarge",
        VCPU:         36,
        MemoryMb:     73728,
        GPU:          0,
        MaxPods:      234,
    },
    "c5d.large": {
        InstanceType: "c5d.large",
        VCPU:         2,
        MemoryMb:     4096,
        GPU:          0,
        MaxPods:      29,
    },
    "c5d.xlarge": {
        InstanceType: "c5d.xlarge",
        VCPU:         4,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      58,
    },
    "c5n": {
        InstanceType: "c5n",
        VCPU:         72,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.18xlarge": {
        InstanceType: "c5n.18xlarge",
        VCPU:         72,
        MemoryMb:     196608,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.2xlarge": {
        InstanceType: "c5n.2xlarge",
        VCPU:         8,
        MemoryMb:     21504,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.4xlarge": {
        InstanceType: "c5n.4xlarge",
        VCPU:         16,
        MemoryMb:     43008,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.9xlarge": {
        InstanceType: "c5n.9xlarge",
        VCPU:         36,
        MemoryMb:     98304,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.large": {
        InstanceType: "c5n.large",
        VCPU:         2,
        MemoryMb:     5376,
        GPU:          0,
        MaxPods:      0,
    },
    "c5n.xlarge": {
        InstanceType: "c5n.xlarge",
        VCPU:         4,
        MemoryMb:     10752,
        GPU:          0,
        MaxPods:      0,
    },
    "cc2.8xlarge": {
        InstanceType: "cc2.8xlarge",
        VCPU:         32,
        MemoryMb:     61952,
        GPU:          0,
        MaxPods:      234,
    },
    "cr1.8xlarge": {
        InstanceType: "cr1.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "d2": {
        InstanceType: "d2",
        VCPU:         36,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "d2.2xlarge": {
        InstanceType: "d2.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          0,
        MaxPods:      58,
    },
    "d2.4xlarge": {
        InstanceType: "d2.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      234,
    },
    "d2.8xlarge": {
        InstanceType: "d2.8xlarge",
        VCPU:         36,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "d2.xlarge": {
        InstanceType: "d2.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "f1": {
        InstanceType: "f1",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "f1.16xlarge": {
        InstanceType: "f1.16xlarge",
        VCPU:         64,
        MemoryMb:     999424,
        GPU:          0,
        MaxPods:      394,
    },
    "f1.2xlarge": {
        InstanceType: "f1.2xlarge",
        VCPU:         8,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      58,
    },
    "f1.4xlarge": {
        InstanceType: "f1.4xlarge",
        VCPU:         16,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "g2": {
        InstanceType: "g2",
        VCPU:         32,
        MemoryMb:     0,
        GPU:          4,
        MaxPods:      0,
    },
    "g2.2xlarge": {
        InstanceType: "g2.2xlarge",
        VCPU:         8,
        MemoryMb:     15360,
        GPU:          1,
        MaxPods:      58,
    },
    "g2.8xlarge": {
        InstanceType: "g2.8xlarge",
        VCPU:         32,
        MemoryMb:     61440,
        GPU:          4,
        MaxPods:      234,
    },
    "g3": {
        InstanceType: "g3",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          4,
        MaxPods:      0,
    },
    "g3.16xlarge": {
        InstanceType: "g3.16xlarge",
        VCPU:         64,
        MemoryMb:     499712,
        GPU:          4,
        MaxPods:      737,
    },
    "g3.4xlarge": {
        InstanceType: "g3.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          1,
        MaxPods:      234,
    },
    "g3.8xlarge": {
        InstanceType: "g3.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          2,
        MaxPods:      234,
    },
    "g3s.xlarge": {
        InstanceType: "g3s.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "h1": {
        InstanceType: "h1",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "h1.16xlarge": {
        InstanceType: "h1.16xlarge",
        VCPU:         64,
        MemoryMb:     262144,
        GPU:          0,
        MaxPods:      737,
    },
    "h1.2xlarge": {
        InstanceType: "h1.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "h1.4xlarge": {
        InstanceType: "h1.4xlarge",
        VCPU:         16,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      234,
    },
    "h1.8xlarge": {
        InstanceType: "h1.8xlarge",
        VCPU:         32,
        MemoryMb:     131072,
        GPU:          0,
        MaxPods:      234,
    },
    "hs1.8xlarge": {
        InstanceType: "hs1.8xlarge",
        VCPU:         17,
        MemoryMb:     119808,
        GPU:          0,
        MaxPods:      234,
    },
    "i2": {
        InstanceType: "i2",
        VCPU:         32,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "i2.2xlarge": {
        InstanceType: "i2.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          0,
        MaxPods:      58,
    },
    "i2.4xlarge": {
        InstanceType: "i2.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      234,
    },
    "i2.8xlarge": {
        InstanceType: "i2.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "i2.xlarge": {
        InstanceType: "i2.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "i3": {
        InstanceType: "i3",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "i3.16xlarge": {
        InstanceType: "i3.16xlarge",
        VCPU:         64,
        MemoryMb:     499712,
        GPU:          0,
        MaxPods:      737,
    },
    "i3.2xlarge": {
        InstanceType: "i3.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          0,
        MaxPods:      58,
    },
    "i3.4xlarge": {
        InstanceType: "i3.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      234,
    },
    "i3.8xlarge": {
        InstanceType: "i3.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "i3.large": {
        InstanceType: "i3.large",
        VCPU:         2,
        MemoryMb:     15616,
        GPU:          0,
        MaxPods:      29,
    },
    "i3.metal": {
        InstanceType: "i3.metal",
        VCPU:         72,
        MemoryMb:     524288,
        GPU:          0,
        MaxPods:      737,
    },
    "i3.xlarge": {
        InstanceType: "i3.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "m1.large": {
        InstanceType: "m1.large",
        VCPU:         2,
        MemoryMb:     7680,
        GPU:          0,
        MaxPods:      29,
    },
    "m1.medium": {
        InstanceType: "m1.medium",
        VCPU:         1,
        MemoryMb:     3840,
        GPU:          0,
        MaxPods:      12,
    },
    "m1.small": {
        InstanceType: "m1.small",
        VCPU:         1,
        MemoryMb:     1740,
        GPU:          0,
        MaxPods:      8,
    },
    "m1.xlarge": {
        InstanceType: "m1.xlarge",
        VCPU:         4,
        MemoryMb:     15360,
        GPU:          0,
        MaxPods:      58,
    },
    "m2.2xlarge": {
        InstanceType: "m2.2xlarge",
        VCPU:         4,
        MemoryMb:     35020,
        GPU:          0,
        MaxPods:      118,
    },
    "m2.4xlarge": {
        InstanceType: "m2.4xlarge",
        VCPU:         8,
        MemoryMb:     70041,
        GPU:          0,
        MaxPods:      234,
    },
    "m2.xlarge": {
        InstanceType: "m2.xlarge",
        VCPU:         2,
        MemoryMb:     17510,
        GPU:          0,
        MaxPods:      58,
    },
    "m3": {
        InstanceType: "m3",
        VCPU:         8,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "m3.2xlarge": {
        InstanceType: "m3.2xlarge",
        VCPU:         8,
        MemoryMb:     30720,
        GPU:          0,
        MaxPods:      118,
    },
    "m3.large": {
        InstanceType: "m3.large",
        VCPU:         2,
        MemoryMb:     7680,
        GPU:          0,
        MaxPods:      29,
    },
    "m3.medium": {
        InstanceType: "m3.medium",
        VCPU:         1,
        MemoryMb:     3840,
        GPU:          0,
        MaxPods:      12,
    },
    "m3.xlarge": {
        InstanceType: "m3.xlarge",
        VCPU:         4,
        MemoryMb:     15360,
        GPU:          0,
        MaxPods:      58,
    },
    "m4": {
        InstanceType: "m4",
        VCPU:         40,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "m4.10xlarge": {
        InstanceType: "m4.10xlarge",
        VCPU:         40,
        MemoryMb:     163840,
        GPU:          0,
        MaxPods:      234,
    },
    "m4.16xlarge": {
        InstanceType: "m4.16xlarge",
        VCPU:         64,
        MemoryMb:     262144,
        GPU:          0,
        MaxPods:      234,
    },
    "m4.2xlarge": {
        InstanceType: "m4.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "m4.4xlarge": {
        InstanceType: "m4.4xlarge",
        VCPU:         16,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      234,
    },
    "m4.large": {
        InstanceType: "m4.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      20,
    },
    "m4.xlarge": {
        InstanceType: "m4.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "m5": {
        InstanceType: "m5",
        VCPU:         96,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "m5.12xlarge": {
        InstanceType: "m5.12xlarge",
        VCPU:         48,
        MemoryMb:     196608,
        GPU:          0,
        MaxPods:      234,
    },
    "m5.24xlarge": {
        InstanceType: "m5.24xlarge",
        VCPU:         96,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      737,
    },
    "m5.2xlarge": {
        InstanceType: "m5.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "m5.4xlarge": {
        InstanceType: "m5.4xlarge",
        VCPU:         16,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      234,
    },
    "m5.large": {
        InstanceType: "m5.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      29,
    },
    "m5.xlarge": {
        InstanceType: "m5.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "m5a.12xlarge": {
        InstanceType: "m5a.12xlarge",
        VCPU:         48,
        MemoryMb:     196608,
        GPU:          0,
        MaxPods:      234,
    },
    "m5a.24xlarge": {
        InstanceType: "m5a.24xlarge",
        VCPU:         96,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      737,
    },
    "m5a.2xlarge": {
        InstanceType: "m5a.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "m5a.4xlarge": {
        InstanceType: "m5a.4xlarge",
        VCPU:         16,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      234,
    },
    "m5a.large": {
        InstanceType: "m5a.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      29,
    },
    "m5a.xlarge": {
        InstanceType: "m5a.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "m5d": {
        InstanceType: "m5d",
        VCPU:         96,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "m5d.12xlarge": {
        InstanceType: "m5d.12xlarge",
        VCPU:         48,
        MemoryMb:     196608,
        GPU:          0,
        MaxPods:      234,
    },
    "m5d.24xlarge": {
        InstanceType: "m5d.24xlarge",
        VCPU:         96,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      737,
    },
    "m5d.2xlarge": {
        InstanceType: "m5d.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "m5d.4xlarge": {
        InstanceType: "m5d.4xlarge",
        VCPU:         16,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      234,
    },
    "m5d.large": {
        InstanceType: "m5d.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      29,
    },
    "m5d.xlarge": {
        InstanceType: "m5d.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      58,
    },
    "p2": {
        InstanceType: "p2",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          16,
        MaxPods:      0,
    },
    "p2.16xlarge": {
        InstanceType: "p2.16xlarge",
        VCPU:         64,
        MemoryMb:     786432,
        GPU:          16,
        MaxPods:      234,
    },
    "p2.8xlarge": {
        InstanceType: "p2.8xlarge",
        VCPU:         32,
        MemoryMb:     499712,
        GPU:          8,
        MaxPods:      234,
    },
    "p2.xlarge": {
        InstanceType: "p2.xlarge",
        VCPU:         4,
        MemoryMb:     62464,
        GPU:          1,
        MaxPods:      58,
    },
    "p3": {
        InstanceType: "p3",
        VCPU:         64,
        MemoryMb:     499712,
        GPU:          8,
        MaxPods:      0,
    },
    "p3.16xlarge": {
        InstanceType: "p3.16xlarge",
        VCPU:         64,
        MemoryMb:     499712,
        GPU:          8,
        MaxPods:      234,
    },
    "p3.2xlarge": {
        InstanceType: "p3.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          1,
        MaxPods:      58,
    },
    "p3.8xlarge": {
        InstanceType: "p3.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          4,
        MaxPods:      234,
    },
    "p3dn": {
        InstanceType: "p3dn",
        VCPU:         96,
        MemoryMb:     786432,
        GPU:          8,
        MaxPods:      0,
    },
    "p3dn.24xlarge": {
        InstanceType: "p3dn.24xlarge",
        VCPU:         96,
        MemoryMb:     786432,
        GPU:          8,
        MaxPods:      0,
    },
    "r3": {
        InstanceType: "r3",
        VCPU:         32,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "r3.2xlarge": {
        InstanceType: "r3.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          0,
        MaxPods:      58,
    },
    "r3.4xlarge": {
        InstanceType: "r3.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      234,
    },
    "r3.8xlarge": {
        InstanceType: "r3.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "r3.large": {
        InstanceType: "r3.large",
        VCPU:         2,
        MemoryMb:     15616,
        GPU:          0,
        MaxPods:      29,
    },
    "r3.xlarge": {
        InstanceType: "r3.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "r4": {
        InstanceType: "r4",
        VCPU:         64,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "r4.16xlarge": {
        InstanceType: "r4.16xlarge",
        VCPU:         64,
        MemoryMb:     499712,
        GPU:          0,
        MaxPods:      737,
    },
    "r4.2xlarge": {
        InstanceType: "r4.2xlarge",
        VCPU:         8,
        MemoryMb:     62464,
        GPU:          0,
        MaxPods:      58,
    },
    "r4.4xlarge": {
        InstanceType: "r4.4xlarge",
        VCPU:         16,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      234,
    },
    "r4.8xlarge": {
        InstanceType: "r4.8xlarge",
        VCPU:         32,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      234,
    },
    "r4.large": {
        InstanceType: "r4.large",
        VCPU:         2,
        MemoryMb:     15616,
        GPU:          0,
        MaxPods:      29,
    },
    "r4.xlarge": {
        InstanceType: "r4.xlarge",
        VCPU:         4,
        MemoryMb:     31232,
        GPU:          0,
        MaxPods:      58,
    },
    "r5": {
        InstanceType: "r5",
        VCPU:         96,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "r5.12xlarge": {
        InstanceType: "r5.12xlarge",
        VCPU:         48,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      234,
    },
    "r5.24xlarge": {
        InstanceType: "r5.24xlarge",
        VCPU:         96,
        MemoryMb:     786432,
        GPU:          0,
        MaxPods:      737,
    },
    "r5.2xlarge": {
        InstanceType: "r5.2xlarge",
        VCPU:         8,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      58,
    },
    "r5.4xlarge": {
        InstanceType: "r5.4xlarge",
        VCPU:         16,
        MemoryMb:     131072,
        GPU:          0,
        MaxPods:      234,
    },
    "r5.large": {
        InstanceType: "r5.large",
        VCPU:         2,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      29,
    },
    "r5.xlarge": {
        InstanceType: "r5.xlarge",
        VCPU:         4,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "r5a.12xlarge": {
        InstanceType: "r5a.12xlarge",
        VCPU:         48,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      234,
    },
    "r5a.24xlarge": {
        InstanceType: "r5a.24xlarge",
        VCPU:         96,
        MemoryMb:     786432,
        GPU:          0,
        MaxPods:      737,
    },
    "r5a.2xlarge": {
        InstanceType: "r5a.2xlarge",
        VCPU:         8,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      58,
    },
    "r5a.4xlarge": {
        InstanceType: "r5a.4xlarge",
        VCPU:         16,
        MemoryMb:     131072,
        GPU:          0,
        MaxPods:      234,
    },
    "r5a.large": {
        InstanceType: "r5a.large",
        VCPU:         2,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      29,
    },
    "r5a.xlarge": {
        InstanceType: "r5a.xlarge",
        VCPU:         4,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "r5d": {
        InstanceType: "r5d",
        VCPU:         96,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "r5d.12xlarge": {
        InstanceType: "r5d.12xlarge",
        VCPU:         48,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      234,
    },
    "r5d.24xlarge": {
        InstanceType: "r5d.24xlarge",
        VCPU:         96,
        MemoryMb:     786432,
        GPU:          0,
        MaxPods:      737,
    },
    "r5d.2xlarge": {
        InstanceType: "r5d.2xlarge",
        VCPU:         8,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      58,
    },
    "r5d.4xlarge": {
        InstanceType: "r5d.4xlarge",
        VCPU:         16,
        MemoryMb:     131072,
        GPU:          0,
        MaxPods:      234,
    },
    "r5d.large": {
        InstanceType: "r5d.large",
        VCPU:         2,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      29,
    },
    "r5d.xlarge": {
        InstanceType: "r5d.xlarge",
        VCPU:         4,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
    "t1.micro": {
        InstanceType: "t1.micro",
        VCPU:         1,
        MemoryMb:     627,
        GPU:          0,
        MaxPods:      4,
    },
    "t2.2xlarge": {
        InstanceType: "t2.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      44,
    },
    "t2.large": {
        InstanceType: "t2.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      35,
    },
    "t2.medium": {
        InstanceType: "t2.medium",
        VCPU:         2,
        MemoryMb:     4096,
        GPU:          0,
        MaxPods:      17,
    },
    "t2.micro": {
        InstanceType: "t2.micro",
        VCPU:         1,
        MemoryMb:     1024,
        GPU:          0,
        MaxPods:      4,
    },
    "t2.nano": {
        InstanceType: "t2.nano",
        VCPU:         1,
        MemoryMb:     512,
        GPU:          0,
        MaxPods:      4,
    },
    "t2.small": {
        InstanceType: "t2.small",
        VCPU:         1,
        MemoryMb:     2048,
        GPU:          0,
        MaxPods:      8,
    },
    "t2.xlarge": {
        InstanceType: "t2.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      44,
    },
    "t3.2xlarge": {
        InstanceType: "t3.2xlarge",
        VCPU:         8,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      44,
    },
    "t3.large": {
        InstanceType: "t3.large",
        VCPU:         2,
        MemoryMb:     8192,
        GPU:          0,
        MaxPods:      35,
    },
    "t3.medium": {
        InstanceType: "t3.medium",
        VCPU:         2,
        MemoryMb:     4096,
        GPU:          0,
        MaxPods:      17,
    },
    "t3.micro": {
        InstanceType: "t3.micro",
        VCPU:         2,
        MemoryMb:     1024,
        GPU:          0,
        MaxPods:      4,
    },
    "t3.nano": {
        InstanceType: "t3.nano",
        VCPU:         2,
        MemoryMb:     512,
        GPU:          0,
        MaxPods:      4,
    },
    "t3.small": {
        InstanceType: "t3.small",
        VCPU:         2,
        MemoryMb:     2048,
        GPU:          0,
        MaxPods:      8,
    },
    "t3.xlarge": {
        InstanceType: "t3.xlarge",
        VCPU:         4,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      44,
    },
    "u-12tb1": {
        InstanceType: "u-12tb1",
        VCPU:         448,
        MemoryMb:     12582912,
        GPU:          0,
        MaxPods:      0,
    },
    "u-6tb1": {
        InstanceType: "u-6tb1",
        VCPU:         448,
        MemoryMb:     6291456,
        GPU:          0,
        MaxPods:      0,
    },
    "u-9tb1": {
        InstanceType: "u-9tb1",
        VCPU:         448,
        MemoryMb:     9437184,
        GPU:          0,
        MaxPods:      0,
    },
    "x1": {
        InstanceType: "x1",
        VCPU:         128,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "x1.16xlarge": {
        InstanceType: "x1.16xlarge",
        VCPU:         64,
        MemoryMb:     999424,
        GPU:          0,
        MaxPods:      234,
    },
    "x1.32xlarge": {
        InstanceType: "x1.32xlarge",
        VCPU:         128,
        MemoryMb:     1998848,
        GPU:          0,
        MaxPods:      234,
    },
    "x1e": {
        InstanceType: "x1e",
        VCPU:         128,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "x1e.16xlarge": {
        InstanceType: "x1e.16xlarge",
        VCPU:         64,
        MemoryMb:     1998848,
        GPU:          0,
        MaxPods:      234,
    },
    "x1e.2xlarge": {
        InstanceType: "x1e.2xlarge",
        VCPU:         8,
        MemoryMb:     249856,
        GPU:          0,
        MaxPods:      58,
    },
    "x1e.32xlarge": {
        InstanceType: "x1e.32xlarge",
        VCPU:         128,
        MemoryMb:     3997696,
        GPU:          0,
        MaxPods:      234,
    },
    "x1e.4xlarge": {
        InstanceType: "x1e.4xlarge",
        VCPU:         16,
        MemoryMb:     499712,
        GPU:          0,
        MaxPods:      58,
    },
    "x1e.8xlarge": {
        InstanceType: "x1e.8xlarge",
        VCPU:         32,
        MemoryMb:     999424,
        GPU:          0,
        MaxPods:      58,
    },
    "x1e.xlarge": {
        InstanceType: "x1e.xlarge",
        VCPU:         4,
        MemoryMb:     124928,
        GPU:          0,
        MaxPods:      29,
    },
    "z1d": {
        InstanceType: "z1d",
        VCPU:         48,
        MemoryMb:     0,
        GPU:          0,
        MaxPods:      0,
    },
    "z1d.12xlarge": {
        InstanceType: "z1d.12xlarge",
        VCPU:         48,
        MemoryMb:     393216,
        GPU:          0,
        MaxPods:      737,
    },
    "z1d.2xlarge": {
        InstanceType: "z1d.2xlarge",
        VCPU:         8,
        MemoryMb:     65536,
        GPU:          0,
        MaxPods:      58,
    },
    "z1d.3xlarge": {
        InstanceType: "z1d.3xlarge",
        VCPU:         12,
        MemoryMb:     98304,
        GPU:          0,
        MaxPods:      234,
    },
    "z1d.6xlarge": {
        InstanceType: "z1d.6xlarge",
        VCPU:         24,
        MemoryMb:     196608,
        GPU:          0,
        MaxPods:      234,
    },
    "z1d.large": {
        InstanceType: "z1d.large",
        VCPU:         2,
        MemoryMb:     16384,
        GPU:          0,
        MaxPods:      29,
    },
    "z1d.xlarge": {
        InstanceType: "z1d.xlarge",
        VCPU:         4,
        MemoryMb:     32768,
        GPU:          0,
        MaxPods:      58,
    },
}

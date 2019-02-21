/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package aws

import (
	// log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func (s *Stack) createSecurityGroup(vpcID string, name string) (string, error) {
	out, err := c.EC2.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName: aws.String(name),
		VpcId:     aws.String(vpcID),
	})
	if err != nil {
		return "", err
	}
	_, err = c.EC2.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}

	_, err = c.EC2.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}
	return *out.GroupId, nil
}

package tests

import (
	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/CS-SI/SafeScale/iaas/stacks/aws"
	"github.com/CS-SI/SafeScale/iaas/stacks/erbc"
	"github.com/CS-SI/SafeScale/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/iaas/stacks/libvirt"
	"github.com/CS-SI/SafeScale/iaas/stacks/openstack"
	"testing"
)

func TestMain(m *testing.M) {
	var stack stacks.Stack

	stack = &local.Stack{}
	stack = &huaweicloud.Stack{}
	stack = &erbc.StackErbc{}
	stack = &openstack.Stack{}
	stack = &aws.Stack{}

	_ = stack
}

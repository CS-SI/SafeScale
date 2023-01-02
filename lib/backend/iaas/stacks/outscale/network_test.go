package outscale

import (
	"testing"

	"github.com/outscale/osc-sdk-go/osc"
)

func Test_NetworkPermissions(t *testing.T) {
	rules := generatePermissions()

	sshRule := osc.SecurityGroupRule{
		FromPortRange: 22,
		ToPortRange:   22,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "tcp",
	}

	icmpRule := osc.SecurityGroupRule{
		FromPortRange: -1,
		ToPortRange:   -1,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "icmp",
	}

	if !checkRule(rules, sshRule) {
		t.Errorf("SSH rule not in default rules")
		t.FailNow()
	}
	if !checkRule(rules, icmpRule) {
		t.Errorf("ICMP rule not in default rules")
		t.FailNow()
	}
}

func checkRule(rules []osc.SecurityGroupRule, rule osc.SecurityGroupRule) bool {
	for _, r := range rules {
		if sameRule(r, rule) {
			return true
		}
	}
	return false
}

func sameRule(rule1 osc.SecurityGroupRule, rule2 osc.SecurityGroupRule) bool {
	if rule1.FromPortRange == rule2.FromPortRange {
		if rule1.ToPortRange == rule2.ToPortRange {
			if rule1.IpProtocol == rule2.IpProtocol {
				return true
			}
		}
	}
	return false
}

package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strconv"
)

func NewTerraformSecurityGroup(svc iaas.Service) (*TfSecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	inctx := context.Background()
	cfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error recovering cfg")
	}

	maybe, there := cfg.Get("TerraformCfg")
	if !there {
		return nil, fail.NewError("terraform configuration not found")
	}

	tops, ok := maybe.(stacks.TerraformOptions)
	if !ok {
		return nil, fail.NewError("unexpected cast problem")
	}

	return &TfSecurityGroup{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
		Tags:                        make(map[string]string),
	}, nil
}

type TfSecurityGroup struct {
	svc iaas.Service

	Name     string
	Identity string

	priorities []int

	terraformExecutableFullPath string
	terraformWorkingDirectory   string
	Location                    string
	Tags                        map[string]string
	networkName                 string
	Rules                       []map[string]interface{}
}

func (t TfSecurityGroup) IsNull() bool {
	return false
}

func (t TfSecurityGroup) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfSecurityGroup) Service() iaas.Service {
	return t.svc
}

func (t TfSecurityGroup) GetID() (string, error) {
	return t.Identity, nil
}

func (t TfSecurityGroup) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfSecurityGroup) GetName() string {
	return t.Name
}

func (t TfSecurityGroup) AddRule(ctx context.Context, rule *abstract.SecurityGroupRule) fail.Error {
	logrus.Warningf("AddRule: %s", litter.Sdump(rule))

	err := renderTerraformRuleFromFiles(ctx, t.svc, t.terraformWorkingDirectory, t, rule)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfSecurityGroup) AddRules(ctx context.Context, rules abstract.SecurityGroupRules) fail.Error {
	for _, rule := range rules {
		err := renderTerraformRuleFromFiles(ctx, t.svc, t.terraformWorkingDirectory, t, rule)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfSecurityGroup) BindToHost(ctx context.Context, host resources.Host, activation resources.SecurityGroupActivation, mark resources.SecurityGroupMark) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) BindToSubnet(ctx context.Context, subnet resources.Subnet, activation resources.SecurityGroupActivation, mark resources.SecurityGroupMark) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Browse(ctx context.Context, callback func(*abstract.SecurityGroup) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSecurityGroup) Clear(ctx context.Context) fail.Error {
	return fail.NewError("useless method") // nobody ever called this method
}

func (t *TfSecurityGroup) Create(ctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules) fail.Error {
	err := renderTerraformSGFromFiles(ctx, t.svc, t.terraformWorkingDirectory, networkID, name, description, rules)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleanup, err := createTerraformSG(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return fail.NewErrorList([]error{err, cerr})
		}
		return fail.ConvertError(err)
	}

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		return xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.SecurityGroupResource, tfstate, t, name)
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil
}

func (t TfSecurityGroup) Delete(ctx context.Context, force bool) fail.Error {
	// FIXME: Delete the firewall rules first

	sgFile := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.networkName), fmt.Sprintf("secgroup-%s", t.Name))

	// if the file doesn't exist, the security group has already been deleted
	if _, err := os.Stat(sgFile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fail.ConvertError(err)
	}

	err := os.Remove(sgFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail.ConvertError(err)
		}
	}

	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfSecurityGroup) DeleteRule(ctx context.Context, rule *abstract.SecurityGroupRule) fail.Error {
	directory := t.terraformWorkingDirectory

	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", t.networkName))
	fullPath := filepath.Join(workDir, fmt.Sprintf("firewallrule-%s.tf", rule.Name))

	err := os.Remove(fullPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail.ConvertError(err)
		}
	}

	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, directory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfSecurityGroup) GetBoundHosts(ctx context.Context) ([]*propertiesv1.SecurityGroupBond, fail.Error) {
	return nil, fail.NewError("useless method") // nobody ever called this method
}

func (t TfSecurityGroup) GetBoundSubnets(ctx context.Context) ([]*propertiesv1.SecurityGroupBond, fail.Error) {
	return nil, fail.NewError("useless method") // nobody ever called this method
}

func (t TfSecurityGroup) Reset(ctx context.Context) fail.Error {
	return fail.NewError("useless method") // nobody ever called this method
}

func (t TfSecurityGroup) ToProtocol(ctx context.Context) (*protocol.SecurityGroupResponse, fail.Error) {
	var protocolRules []*protocol.SecurityGroupRule
	for _, rule := range t.Rules {
		var direction protocol.SecurityGroupRuleDirection
		switch rule["direction"].(string) {
		case "Inbound":
			direction = protocol.SecurityGroupRuleDirection_SGRD_INGRESS
		case "Outbound":
			direction = protocol.SecurityGroupRuleDirection_SGRD_EGRESS
		default:
			return nil, fail.NewError("invalid direction '%s'", rule["direction"].(string))
		}

		pfrom, _ := strconv.Atoi(rule["destination_port_range"].(string))

		protocolRules = append(protocolRules, &protocol.SecurityGroupRule{
			Description: rule["description"].(string),
			EtherType:   4,
			Direction:   direction,
			Protocol:    rule["protocol"].(string),
			PortFrom:    int32(pfrom),
			PortTo:      int32(pfrom),
		})
	}

	return &protocol.SecurityGroupResponse{
		Id:          t.Identity,
		Name:        t.Name,
		Description: "",
		Rules:       protocolRules,
	}, nil
}

func (t TfSecurityGroup) UnbindFromHost(ctx context.Context, host resources.Host) fail.Error {
	return fail.NewError("useless method") // does not make sense in terraform azure driver
}

func (t TfSecurityGroup) UnbindFromHostByReference(ctx context.Context, s string) fail.Error {
	return fail.NewError("useless method") // nobody ever called this method
}

func (t TfSecurityGroup) UnbindFromSubnet(ctx context.Context, subnet resources.Subnet) fail.Error {
	return fail.NewError("useless method") // does not make sense in terraform azure driver
}

func (t TfSecurityGroup) UnbindFromSubnetByReference(ctx context.Context, s string) fail.Error {
	return fail.NewError("useless method") // does not make sense in terraform azure driver
}

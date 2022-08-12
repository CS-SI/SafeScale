package huaweicloud

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func Test_validateHostname(t *testing.T) {
	type args struct {
		req abstract.HostRequest
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 fail.Error
	}{
		{"empty test", args{abstract.HostRequest{ResourceName: ""}}, false, fail.Wrap(fmt.Errorf("ResourceName: cannot be blank."), "validation issue")},
		{"right length", args{abstract.HostRequest{ResourceName: "eventually"}}, true, nil},
		{"wrong content", args{abstract.HostRequest{ResourceName: "even//tually"}}, false, fail.Wrap(fmt.Errorf("ResourceName: must be in a valid format."), "validation issue")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := validateHostname(tt.args.req)
			if got != tt.want {
				t.Errorf("validateHostname() got = %v, want %v", got, tt.want)
			}
			if tt.want1 != nil && got1 == nil {
				t.Errorf("mismatch: %s", tt.want1)
			}
			if tt.want1 == nil && got1 != nil {
				t.Errorf("mismatch: %s", got1)
			}
			if got1 != nil && tt.want1 != nil {
				if !reflect.DeepEqual(got1.Error(), tt.want1.Error()) {
					t.Errorf("validateHostname() got1 = %v, want %v", got1, tt.want1)
				}
			}
		})
	}
}

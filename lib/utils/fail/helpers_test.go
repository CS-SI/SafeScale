package fail

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

func TestIsNull(t *testing.T) {
	var err error
	var ptrerr *error
	var dblptrerr **error

	var ourErr Error
	var ptrOurErr *Error
	var dblptrOurErr **Error

	var ourConcreteErr ErrNotFound
	var ptrOurConcreteErr *ErrNotFound
	var dlbPtrOurConcreteErr **ErrNotFound

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"nil", args{nil}, true},
		{"raw errors 1", args{err}, true},
		{"raw errors 2", args{ptrerr}, true},
		{"raw errors 3", args{dblptrerr}, true},
		{"our errors 1", args{ourErr}, true},
		{"our errors 2", args{ptrOurErr}, true},
		{"our errors 3", args{dblptrOurErr}, true},
		{"our concrete errors 1", args{ourConcreteErr}, true},
		{"our concrete errors 2", args{ptrOurConcreteErr}, true},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNull(tt.args.something); got != tt.want {
				t.Errorf("IsNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotNulls(t *testing.T) {
	var err = fmt.Errorf("")
	var ptrerr = &err
	var dblptrerr = &ptrerr

	var ourErr = NewError("")
	var ptrOurErr = &ourErr
	var dblptrOurErr = &ptrOurErr

	var ptrOurConcreteErr = NotFoundError("")
	var ourConcreteErr = *ptrOurConcreteErr
	var dlbPtrOurConcreteErr = &ptrOurConcreteErr

	var emptyStrArray []string

	type brand struct {
		content string
	}

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"string", args{"whatever"}, false},
		{"array of string", args{[]string{"whatever"}}, false},
		{"array of string empty", args{[]string{}}, false},
		{"array of string empty not initialized", args{emptyStrArray}, false},
		{"struct 1", args{brand{}}, true},
		{"struct 2", args{brand{content: ""}}, true},
		{"ptr struct", args{&brand{}}, false},
		{"raw errors 1", args{err}, false},
		{"raw errors 2", args{ptrerr}, false},
		{"raw errors 3", args{dblptrerr}, false},
		{"our errors 1", args{ourErr}, false},
		{"our errors 2", args{ptrOurErr}, false},
		{"our errors 3", args{dblptrOurErr}, false},
		{"our concrete errors 1", args{ourConcreteErr}, false},
		{"our concrete errors 2", args{ptrOurConcreteErr}, false},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNull(tt.args.something); got != tt.want {
				t.Errorf("IsNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

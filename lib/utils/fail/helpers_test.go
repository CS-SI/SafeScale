package fail

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/stretchr/testify/require"
)

type NullableInterface interface {
	IsNull() bool
}
type Nullable struct {
	NullableInterface
	isnull bool
}

func (e Nullable) IsNull() bool {
	return e.isnull
}

type NillableInterface interface {
	IsNil() bool
}
type Nillable struct {
	NillableInterface
	isnil bool
}

func (e Nillable) IsNil() bool {
	return e.isnil
}

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
	var err error = fmt.Errorf("")
	var ptrerr *error = &err
	var dblptrerr **error = &ptrerr

	var ourErr Error = NewError("")
	var ptrOurErr *Error = &ourErr
	var dblptrOurErr **Error = &ptrOurErr

	var ptrOurConcreteErr *ErrNotFound = NotFoundError("")
	var ourConcreteErr ErrNotFound = *ptrOurConcreteErr
	var dlbPtrOurConcreteErr **ErrNotFound = &ptrOurConcreteErr

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
		{"struct", args{brand{}}, false},
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

func Test_IsNil(t *testing.T) {

	var a_null Nullable
	var a_nil Nillable
	var p_null *Nullable = nil
	var p_nil *Nillable = nil

	require.EqualValues(t, IsNil(nil), true)
	require.EqualValues(t, IsNil(a_null), false)
	require.EqualValues(t, IsNil(p_null), true)
	require.EqualValues(t, IsNil(Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(&Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(&Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(a_nil), false)
	require.EqualValues(t, IsNil(p_nil), true)
	require.EqualValues(t, IsNil(Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(&Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil(&Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil("test"), false)
	require.EqualValues(t, IsNil(&struct {
		Price  float64
		Symbol string
		Rating uint
	}{
		Price:  5.55,
		Symbol: "€",
		Rating: 4,
	}), false)

}

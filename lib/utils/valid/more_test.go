package valid

import (
	"testing"

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

func Test_hasFieldWithNameAndIsNil(t *testing.T) {

	result, _ := hasFieldWithNameAndIsNil(nil, "field")
	require.EqualValues(t, result, false)

	result, _ = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
	}{}, "d")
	require.EqualValues(t, result, false)

	result, _ = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d float64
	}{}, "d")
	require.EqualValues(t, result, false)

	result, _ = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d *float64
	}{
		d: nil,
	}, "d")
	require.EqualValues(t, result, true)

}

func Test_IsNil(t *testing.T) {
	var a_null Nullable
	var a_nil Nillable
	// var p_null *Nullable = nil
	// var p_nil *Nillable = nil

	require.EqualValues(t, IsNil(nil), true)
	require.EqualValues(t, IsNil(a_null), false)
	// require.EqualValues(t, IsNil(p_null), true)
	require.EqualValues(t, IsNil(Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(&Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(&Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(a_nil), false)
	// require.EqualValues(t, IsNil(p_nil), true)
	require.EqualValues(t, IsNil(Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(&Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil(&Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil("test"), false)
	require.EqualValues(t, IsNil(struct{}{}), false)
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

func Test_IsNull(t *testing.T) {
	var a_null Nullable
	var a_nil Nillable
	// var p_null *Nullable = nil
	// var p_nil *Nillable = nil

	require.EqualValues(t, IsNull(nil), true)
	require.EqualValues(t, IsNull(a_null), false)
	// require.EqualValues(t, IsNil(p_null), true)
	require.EqualValues(t, IsNull(Nullable{isnull: true}), true)
	require.EqualValues(t, IsNull(&Nullable{isnull: true}), true)
	require.EqualValues(t, IsNull(Nullable{isnull: false}), false)
	require.EqualValues(t, IsNull(&Nullable{isnull: false}), false)
	require.EqualValues(t, IsNull(a_nil), false)
	// require.EqualValues(t, IsNil(p_nil), true)
	require.EqualValues(t, IsNull(Nillable{isnil: true}), true)
	require.EqualValues(t, IsNull(&Nillable{isnil: true}), true)
	require.EqualValues(t, IsNull(Nillable{isnil: false}), false)
	require.EqualValues(t, IsNull(&Nillable{isnil: false}), false)
	require.EqualValues(t, IsNull("test"), false)
	require.EqualValues(t, IsNull(struct{}{}), false)
	require.EqualValues(t, IsNull(&struct {
		Price  float64
		Symbol string
		Rating uint
	}{
		Price:  5.55,
		Symbol: "€",
		Rating: 4,
	}), false)

}

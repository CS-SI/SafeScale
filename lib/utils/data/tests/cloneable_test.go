package tests

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEasyCloneable(t *testing.T) {
	a := NewStructWithoutPointers()
	a.Content = "easy"
	a.Rumba = 9

	b := a.Clone().(*StructWithoutPointers)

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)

	a.Content = "whatever"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)
}

/*type Memoria struct {
	content []string
	painful int
}

func NewMemoria(num int, cts ...string) *Memoria {
	return &Memoria{
		content: cts[:],
		painful: num,
	}
}

func (m Memoria) Clone() data.Clonable {
	return NewMemoria(0, "").Replace(&m)
}

func (m *Memoria) Replace(clonable data.Clonable) data.Clonable {
	*m = *clonable.(*Memoria)
	return m
}
*/

// This test, if it succeeds, means the Replace implementation is defective
func TestDefectiveCloneableImplementation(t *testing.T) {
	a := NewStructWithPointersAndDefectiveReplace()
	a.Rumba = 9
	a.List = []string{"death", "comes", "to", "all"}
	a.Map = map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	b := a.Clone().(*StructWithPointersAndDefectiveReplace)

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)

	a.List[1] = "despair"
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)
}

func TestValidCloneableImplementation(t *testing.T) {
	a := NewStructWithPointersAndCorrectReplace()
	a.Rumba = 9
	a.List = []string{"death", "comes", "to", "all"}
	a.Map = map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	b := a.Clone().(*StructWithPointersAndCorrectReplace)

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)

	a.List[1] = "despair"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)
}

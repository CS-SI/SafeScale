package main

import(
	"fmt"
	"github.com/davecgh/go-spew/spew"
)
type carryptr struct {
    p1 *int
    p2 int
    p3 interface{}
}

func main() {
    var value int = 20
    var pvalue *int = &value

    cp := carryptr{
	p1: &value,
	p2: value,
	p3: &value,
    }
    spew.Dump(cp)

    cp = carryptr{
	p1: pvalue,
	p2: *pvalue,
	p3: pvalue,
    }
    spew.Dump(cp)

    var anon interface{}
    anon = cp.p3
    spew.Dump(anon)
    v := anon.(*int)
    spew.Dump(v)
    fmt.Println(*v)
}

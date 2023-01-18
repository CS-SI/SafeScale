package iaas

import "testing"

func TestSearchWithRegex(t *testing.T) {
	templates := []string{"a-1", "b-0", "c2-a", "s-3", "c2-X", "s-2", "s-4", "c2-22"}

	res, err := searchRegex("s.*|c2-.*|x1.*", templates)

	if err != nil {
		t.Error(err.Error())
	}

	waitedRes := []string{"s-2", "s-3", "s-4", "c2-22", "c2-X", "c2-a"}

	if len(res) != len(waitedRes) {
		t.Error("Wrong result size")
	}

	for i := 0; i < len(res); i++ {
		if res[i] != waitedRes[i] {
			t.Errorf("Wrong returned element, res : %s  waited : %s", res[i], waitedRes[i])
		}
	}
}

func TestSearchWithRegex2(t *testing.T) {
	templates := []string{"a-1", "b-0", "c2-a", "s-3", "c2-X", "s-2", "s-4", "c2-22"}

	res, err := searchRegex("c2-.*", templates)

	if err != nil {
		t.Error(err.Error())
	}

	waitedRes := []string{"c2-22", "c2-X", "c2-a"}

	if len(res) != len(waitedRes) {
		t.Error("Wrong result size")
	}

	for i := 0; i < len(res); i++ {
		if res[i] != waitedRes[i] {
			t.Errorf("Wrong returned element, res : %s  waited : %s", res[i], waitedRes[i])
		}
	}
}

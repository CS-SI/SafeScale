package template_search

import (
	"regexp"
	"sort"
	"strings"
)

func searchRegex(regex string, templates []string) ([]string, error) {
	regexs := strings.Split(regex, "|")
	tmp := make([][]string, len(regexs))

	for i, r := range regexs {
		for _, k := range templates {
			match, err := regexp.MatchString(r, k)
			if err != nil {
				return nil, err
			}

			if match {
				tmp[i] = append(tmp[i], k)
			}
		}
	}

	var res = make([]string, 0, len(templates))

	for i := 0; i < len(tmp); i++ {
		sort.Strings(tmp[i])
		res = append(res, tmp[i]...)
	}

	return res, nil
}

package server

import (
	"fmt"
	"sort"
	"strings"
)

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]string, len(a))
	copy(as, a)
	bs := make([]string, len(b))
	copy(bs, b)
	sort.Strings(as)
	sort.Strings(bs)
	for i, v := range as {
		if v != bs[i] {
			return false
		}
	}
	return true
}

func compareStringSliceMap(s []string, m map[string]bool) error {
        if s == nil && m == nil {
                return nil
        }
        if len(s) != len(m) {
                return fmt.Errorf("map '%v', slice '%v'", m, s)
        }
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }

        // same length, so compare
        sort.Strings(keys)
        sort.Strings(s)

        sj := strings.Join(s, "\n")
        mj := strings.Join(keys, "\n")
        if sj != mj {
                return fmt.Errorf("mismatched entries, slice '%s', map '%s'", sj, mj)
        }
        return nil
}

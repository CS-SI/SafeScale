package iaas

import "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"

// RankDRF computes the Dominant Resource Fairness Rank of a host template
func RankDRF(t *abstract.HostTemplate) float32 {
	fc := float32(t.Cores)
	fr := t.RAMSize
	fd := float32(t.DiskSize)
	return fc*CoreDRFWeight + fr*RAMDRFWeight + fd*DiskDRFWeight
}

// ByRankDRF implements sort.Interface for []HostTemplate based on
// the Dominant Resource Fairness
type ByRankDRF []*abstract.HostTemplate

func (a ByRankDRF) Len() int      { return len(a) }
func (a ByRankDRF) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less returns what entry is less between indexes i and j, based on rank. If rank is identical, compares entry names
func (a ByRankDRF) Less(i, j int) bool {
	ra := RankDRF(a[i])
	rb := RankDRF(a[j])

	if ra < rb {
		return true
	}

	if ra > rb {
		return false
	}

	return a[i].Name < a[j].Name
}

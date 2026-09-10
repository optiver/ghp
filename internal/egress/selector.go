package egress

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// Candidate describes current load. Active includes response-body streaming.
type Candidate struct {
	Name   string
	Weight int64
	Active int64
}

// Selector chooses a candidate index. The pool serializes calls and owns load
// accounting; selectors must not mutate or retain the candidates slice.
type Selector interface {
	Select(candidates []Candidate, key string) int
}

type roundRobin struct {
	current map[string]int64
	least   bool
}

// Select implements smooth weighted round robin, optionally restricted to the
// least loaded candidates. Cross multiplication avoids floating-point ties.
func (s *roundRobin) Select(cs []Candidate, _ string) int {
	if s.current == nil {
		s.current = make(map[string]int64, len(cs))
	}
	least := 0
	if s.least {
		for i := range cs {
			if cs[i].Active*cs[least].Weight < cs[least].Active*cs[i].Weight {
				least = i
			}
		}
	}
	best, total := -1, int64(0)
	for i, c := range cs {
		if s.least && c.Active*cs[least].Weight != cs[least].Active*c.Weight {
			s.current[c.Name] = 0
			continue
		}
		s.current[c.Name] += c.Weight
		total += c.Weight
		if best == -1 || s.current[c.Name] > s.current[cs[best].Name] {
			best = i
		}
	}
	if best >= 0 {
		s.current[cs[best].Name] -= total
	}
	return best
}

type ipHash struct{ fallback roundRobin }

func (s *ipHash) Select(cs []Candidate, key string) int {
	if key == "" {
		return s.fallback.Select(cs, key)
	}
	best, score := -1, math.Inf(1)
	for i, c := range cs {
		digest := sha256.Sum256([]byte(key + "\x00" + c.Name))
		// Weighted rendezvous hashing: an exponential race gives each member
		// probability proportional to its weight, independent of list order.
		u := (float64(binary.BigEndian.Uint64(digest[:])>>12) + 0.5) / (1 << 52)
		x := -math.Log(u) / float64(c.Weight)
		if x < score || (x == score && (best == -1 || c.Name < cs[best].Name)) {
			best, score = i, x
		}
	}
	return best
}

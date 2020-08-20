// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

type Cover map[uint32]struct{}
type MemCover map[uint64]struct{}

func (cov *Cover) Merge(raw []uint32) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

func (cov Cover) Serialize() []uint32 {
	res := make([]uint32, 0, len(cov))
	for pc := range cov {
		res = append(res, pc)
	}
	return res
}

func RestorePC(pc, base uint32) uint64 {
	return uint64(base)<<32 + uint64(pc)
}

// Pranav
// KMCOV cover functions
func (cov *MemCover) Merge(addrs []uint64, ips []uint64, accessTypes []uint32) {
	c := *cov
	if c == nil {
		c = make(MemCover)
		*cov = c
	}
	for _, addr := range addrs {
		c[addr] = struct{}{}
	}
}

func (cov *MemCover) MaxIp(addrs []uint64, ips []uint64, accessTypes []uint32) (int, int, int, int, int, int) {
	c := *cov
	if c == nil {
		return -1, -1, -1, -1, -1, -1
	}
	ipCount := make(map[uint64]int)
	max, max2, max3, max4, max5 := 0, 0, 0, 0, 0
	for _, addr := range addrs {
		ipCount[addr]++
		if ipCount[addr] > max {
			max5 = max4
			max4 = max3
			max3 = max2
			max2 = max
			max = ipCount[addr]
		}
	}
	return len(ipCount), max, max2, max3, max4, max5
}

func (cov MemCover) Serialize() []uint64 {
	res := make([]uint64, 0, len(cov))
	for addr := range cov {
		res = append(res, addr)
	}
	return res
}

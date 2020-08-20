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

func (cov *MemCover) CountDefineUsePairs(addrs []uint64, ips []uint64, accessTypes []uint32) int {
	ipMap := make(map[uint64][]int)
	for i, addr := range addrs {
		// Todo: remove limit and observe impact
		// if len(ipMap[addr]) >= 1000 {
		// 	continue
		// }
		ipMap[addr] = append(ipMap[addr], i)
	}

	duPairs := 0
	for _, ipIndicies := range ipMap {
		readCount := 0
		// Iterate backwards to make DU pair counting easier
		for i := len(ipIndicies) - 1; i >= 0; i-- {
			// Count reads
			if accessTypes[ipIndicies[i]] == 0 { // Read
				readCount++
			} else { // Write
				duPairs += readCount
			}
		}
	}
	return duPairs
}

// func (cov *MemCover) MaxIp(addrs []uint64, ips []uint64, accessTypes []uint32) (int, int, int, int, int, int) {
// 	c := *cov
// 	if c == nil {
// 		return -1, -1, -1, -1, -1, -1
// 	}
// 	ipCount := make(map[uint64]int)
// 	max, max2, max3, max4, max5 := 0, 0, 0, 0, 0
// 	for _, addr := range addrs {
// 		ipCount[addr]++
// 	}

// 	for _, v := range ipCount {
// 		if v > max {
// 			max5 = max4
// 			max4 = max3
// 			max3 = max2
// 			max2 = max
// 			max = v
// 		}
// 	}
// 	return len(ipCount), max, max2, max3, max4, max5
// }

func (cov MemCover) Serialize() []uint64 {
	res := make([]uint64, 0, len(cov))
	for addr := range cov {
		res = append(res, addr)
	}
	return res
}

// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

import (
	"bytes"
	"encoding/gob"
)

type Cover map[uint32]struct{}
type MemCover map[uint64]struct{}

// Struct representing a unique DU pair. Since DU pairs are defined to be write->read, there is
// no need to keep track of which ip occured first.
type DuPairEntry struct {
	Addr    uint64
	WriteIP uint64
	ReadIP  uint64
}
type DuCover map[DuPairEntry]struct{}

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

/* Pranav: KMCOV cover functions */

func (cov *MemCover) Merge(addrs []uint64) {
	c := *cov
	if c == nil {
		c = make(MemCover)
		*cov = c
	}
	for _, addr := range addrs {
		c[addr] = struct{}{}
	}
}

func (cov MemCover) Serialize() []uint64 {
	res := make([]uint64, 0, len(cov))
	for addr := range cov {
		res = append(res, addr)
	}
	return res
}

func (cov *DuCover) Merge(data []byte) {
	c := *cov
	if c == nil {
		c = make(DuCover)
		*cov = c
	}

	if data == nil || len(data) == 0 {
		return
	}

	entries := deserialize(data)
	for _, entry := range entries {
		c[entry] = struct{}{}
	}
}

// Returns total pairs and number of new unique DU pairs discovered
func (cov *DuCover) ComputeDuCov(addrs []uint64, ips []uint64, accessTypes []uint32) (int, int) {
	c := *cov
	if c == nil {
		c = make(DuCover)
		*cov = c
	}

	if len(addrs) == 0 {
		return 0, 0
	}

	ipMap := make(map[uint64][]int)
	for i, addr := range addrs {
		// Todo: remove limit and observe impact
		// if len(ipMap[addr]) >= 1000 {
		// 	continue
		// }
		ipMap[addr] = append(ipMap[addr], i)
	}

	duPairs := 0
	newUniquePairs := 0
	for memAddr, ipIndicies := range ipMap {
		readCount := 0
		var readIps []uint64
		// Iterate backwards to make DU pair counting easier
		for i := len(ipIndicies) - 1; i >= 0; i-- {
			// Count reads
			if accessTypes[ipIndicies[i]] == 0 { // Read ip
				// Keep track of all read ips for later
				readIps = append(readIps, ips[ipIndicies[i]])
				readCount++
			} else { // Write ip
				// Check uniqueness of DU pair, insert if unique
				unique := 0
				for _, readIP := range readIps {
					pair := DuPairEntry{
						memAddr,
						ips[ipIndicies[i]],
						readIP,
					}
					if _, ok := c[pair]; !ok {
						c[pair] = struct{}{}
						unique++
					}
				}
				duPairs += readCount
				newUniquePairs += unique
			}
		}
	}
	return duPairs, newUniquePairs
}

// Serialize DuCover map into []DuPairEntry into bytes
func (cov *DuCover) Serialize() []byte {
	c := *cov
	if c == nil {
		return nil
	}

	// Convert to slice/list of pairs
	var entries []DuPairEntry
	for entry := range c {
		entries = append(entries, entry)
	}

	// Serialize entry list
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(entries)
	if err != nil {
		return nil
	}
	return data.Bytes()
}

// Deserialize bytes into []DuEntryPair
func deserialize(covData []byte) []DuPairEntry {
	data := bytes.NewBuffer(covData)
	var res []DuPairEntry
	enc := gob.NewDecoder(data)
	err := enc.Decode(&res)
	if err != nil {
		return nil
	}
	return res
}

// O(N) operation
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

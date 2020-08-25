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

// Return a MemCover representing the intersection of the list of addrs
// and the current MemCover. Follows prototype of signal.Intersect.
func (cov *MemCover) Intersection(addrs []uint64) MemCover {
	c := *cov
	if c == nil {
		return MemCover{}
	}
	var intersect MemCover
	for _, addr := range addrs {
		if _, ok := c[addr]; ok {
			intersect[addr] = struct{}{}
		}
	}
	return intersect
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

func (cov *DuCover) MergeMap(cov2 DuCover) {
	c := *cov
	if c == nil {
		c = make(DuCover)
		*cov = c
	}

	if len(cov2) == 0 {
		return
	}

	for pair, _ := range cov2 {
		c[pair] = struct{}{}
	}
}

// Return a DuCover representing the intersection of the argument
// and the current DuCover. Follows prototype of signal.Intersect.
func (cov *DuCover) Intersection(cov2 DuCover) DuCover {
	c := *cov
	if c == nil {
		return DuCover{}
	}
	intersect := make(DuCover)
	for pair := range cov2 {
		if _, ok := c[pair]; ok {
			intersect[pair] = struct{}{}
		}
	}
	return intersect
}

// Computes the number of elements not in (cov and cov2)
func (cov *DuCover) Diff(cov2 DuCover) int {
	c := *cov
	if c == nil {
		return len(cov2)
	}

	if len(cov2) == 0 {
		return len(c)
	}

	intersect := len(cov.Intersection(cov2))
	return (len(c) - intersect) + (len(cov2) - intersect)
}

// Checks if cov is empty
func (cov *DuCover) Empty() bool {
	c := *cov
	if c == nil {
		return true
	}
	return len(c) == 0
}

// Returns total pairs and number of new unique DU pairs discovered. (Technically computing LP
// Pairs as no writes are allowed in between). If previous DuCover is present, merge new du pairs
// into map.
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
				// Do not let every read after every write be a DU pair
				// as, assuming pure sequential execution, the most recent
				// write will always occur after the previous ones, and thus
				// is all that is needed to be considered.
				readIps = nil
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

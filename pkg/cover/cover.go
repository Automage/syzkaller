// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"hash/crc64"

	"github.com/google/syzkaller/pkg/log"
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
	intersect := make(MemCover)
	for _, addr := range addrs {
		if _, ok := c[addr]; ok {
			intersect[addr] = struct{}{}
		}
	}
	return intersect
}

func (cov *MemCover) Serialize() []uint64 {
	c := *cov
	if c == nil {
		return []uint64{}
	}
	res := make([]uint64, 0, len(c))
	for addr := range c {
		res = append(res, addr)
	}
	return res
}

// Computes the number of elements in addrs but not cov
func (cov *MemCover) Diff(addrs []uint64) int {
	c := *cov
	if c == nil {
		return len(addrs)
	}

	if len(addrs) == 0 {
		return 0
	}

	// intersect := len(cov.Intersection(cov2))
	// return (len(c) - intersect) + (len(cov2) - intersect)

	diff := 0
	for _, addr := range addrs {
		if _, ok := c[addr]; !ok {
			diff++
		}
	}

	return diff
}

func (cov *MemCover) Empty() bool {
	c := *cov
	if c == nil {
		return true
	}
	return len(c) == 0
}

/* Pranav: Du Coverage functions */

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

// Computes the number of elements in cov2 but not cov
func (cov *DuCover) Diff(cov2 DuCover) int {
	c := *cov
	if c == nil {
		return len(cov2)
	}

	if len(cov2) == 0 {
		return 0
	}

	// intersect := len(cov.Intersection(cov2))
	// return (len(c) - intersect) + (len(cov2) - intersect)

	diff := 0
	for pair := range cov2 {
		if _, ok := c[pair]; !ok {
			diff++
		}
	}

	return diff
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

/* Hash experiment */

// type HashCover map[uint64]struct{}

const MemBits = 10

func (cov *MemCover) ComputeHashCov(addrs []uint64, ips []uint64, accessTypes []uint32) int {
	c := *cov
	if c == nil {
		c = make(MemCover)
		*cov = c
	}

	ipMask := uint64(0xFFFFFFFF)
	addrMask := uint64((1 << MemBits) - 1)
	total := 0

	for i, addr := range addrs {
		ip := ips[i] % (1 << 32)
		accessType := uint64(accessTypes[i])

		buf := make([]byte, binary.MaxVarintLen64)
		binary.PutUvarint(buf, addr)
		hashAddr := crc64.Checksum(buf, crc64.MakeTable(crc64.ISO))
		truncAddr := hashAddr % (1 << MemBits)

		x := ((ip & ipMask) << 32) | ((truncAddr & addrMask) << 1) | (accessType & uint64(1))
		c[x] = struct{}{}

		if addr != 0 {
			total++
		}
	}

	return total
}

func MaxIp(addrs []uint64, ips []uint64) (uint64, uint64, uint64) {

	ipCount := make(map[uint64]int)
	max := 0
	for _, addr := range addrs {
		ipCount[addr]++
	}
	var amax, amax2, amax3 uint64
	for addr, v := range ipCount {
		if v > max {
			max = v

			amax3 = amax2
			amax2 = amax
			amax = addr
		}
	}

	var ip1, ip2, ip3 uint64
	for i, addr := range addrs {
		if addr == amax {
			ip1 = ips[i]
		}
		if addr == amax2 {
			ip2 = ips[i]
		}
		if addr == amax3 {
			ip3 = ips[i]
		}
	}
	return ip1, ip2, ip3
}

/* Communicated memory coverage experiment */

type ComMemCover map[uint64]uint32 // 0 - read only, 1 - write only, 2 - wr
const MAGIC_COUNT_ENTRY = 7

func (cov *ComMemCover) Compute(addrs []uint64, types []uint32) {
	c := *cov
	if c == nil {
		c = make(ComMemCover)
		*cov = c
	}

	for i, addr := range addrs {
		accessType := types[i]
		if entry, ok := c[addr]; ok {
			if entry != 2 && (accessType != entry) {
				c[addr] = 2
				c[MAGIC_COUNT_ENTRY]++
			}
		} else {
			c[addr] = accessType
		}
	}

}

// TODO: Return addresses too
func (cov *ComMemCover) GetCommunicatedAddrs() int {
	c := *cov
	if c == nil {
		return 0
	}

	return int(c[MAGIC_COUNT_ENTRY])
}

func (cov *ComMemCover) Merge(data []byte) {
	c := *cov
	if c == nil {
		c = make(ComMemCover)
		*cov = c
	}

	deserial := deserializeComMemCov(data)
	c.MergeMap(deserial)

}

func (cov *ComMemCover) MergeMap(cov2 ComMemCover) {
	c := *cov
	if c == nil {
		c = make(ComMemCover)
		*cov = c
	}

	// TODO: ADD COUNTS
	for addr, comState := range cov2 {
		if addr == MAGIC_COUNT_ENTRY {
			continue
		}

		if entry, ok := c[addr]; ok {
			if entry != 2 && entry != comState {
				c[addr] = 2
				c[MAGIC_COUNT_ENTRY]++
			}
		} else {
			if comState == 2 {
				c[MAGIC_COUNT_ENTRY]++
			}
			c[addr] = comState
		}
	}
}

// Serialize ComMemCover map
func (cov *ComMemCover) Serialize() []byte {
	c := *cov
	if c == nil {
		return nil
	}

	// Serialize map
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(c)
	if err != nil {
		return nil
	}
	return data.Bytes()
}

// Deserialize bytes into []DuEntryPair
func deserializeComMemCov(covData []byte) ComMemCover {
	data := bytes.NewBuffer(covData)
	var res ComMemCover
	enc := gob.NewDecoder(data)
	err := enc.Decode(&res)
	if err != nil {
		return nil
	}
	return res
}

/* Endpoint coverage experiment */

type endpoint struct {
	ip         uint64
	accessType bool
}

// type EpCover map[uint64]map[endpoint]struct{}
type EpCover map[uint64]map[uint64]int

const MAGIC_READ_ENTRY = 6
const MAGIC_WRITE_ENTRY = 7

// Merges new data and returns new endpoint pairs discovered
func (cov *EpCover) Merge(addrs []uint64, ips []uint64, types []uint32) int {
	c := *cov
	if c == nil {
		c = make(EpCover)
		*cov = c
	}

	newEPs := 0

	for i, addr := range addrs {
		var pairs int
		c[addr], pairs = tryAddEp(c[addr], ips[i], int(types[i]))
		newEPs += pairs
	}

	log.Logf(3, "Jain : inside ep len %v, pairs %v", len(c), newEPs)
	return newEPs
}

func (cov *EpCover) MergeMap(cov2 EpCover) int {
	c := *cov
	if c == nil {
		c = make(EpCover)
		*cov = c
	}

	newEPs := 0

	for addr, epMap := range cov2 {
		for ip, accessType := range epMap {
			var pairs int
			c[addr], pairs = tryAddEp(c[addr], ip, accessType)
			newEPs += pairs
		}
	}

	return newEPs
}

// func (cov *EpCover) ComputeEpPairs(cov2 EpCover) int {
// 	c := *cov
// 	if c == nil {
// 		return -1
// 	}

// 	pairs := 0
// 	for addr, epMap2 := range cov2 {
// 		// Corpus cover contains endpoints referring to address
// 		if epMap, ok := c[addr]; ok {
// 			pairs +=
// 		}
// 	}
// }

// Inserts an endpoint into epMap
func tryAddEp(im map[uint64]int, ip uint64, accessType int) (map[uint64]int, int) {
	if im == nil {
		im = make(map[uint64]int)
	}

	// Reserved ips
	if ip == MAGIC_WRITE_ENTRY || ip == MAGIC_READ_ENTRY {
		return im, 0
	}

	newEPs := 0
	if _, ok := im[ip]; !ok {
		im[ip] = accessType
		if accessType == 0 { // Read
			newEPs = im[MAGIC_WRITE_ENTRY]
			im[MAGIC_READ_ENTRY]++
		} else if accessType == 1 { // Write
			newEPs = im[MAGIC_READ_ENTRY]
			im[MAGIC_WRITE_ENTRY]++
		}
	}

	return im, newEPs
}

// Serialize EpCover map
func (cov *EpCover) Serialize() []byte {
	c := *cov
	if c == nil {
		return nil
	}

	// Serialize map
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(c)
	if err != nil {
		return nil
	}
	return data.Bytes()
}

// Deserialize bytes into EpCover
func DeserializeEpCov(covData []byte) EpCover {
	data := bytes.NewBuffer(covData)
	var res EpCover
	enc := gob.NewDecoder(data)
	err := enc.Decode(&res)
	if err != nil {
		return nil
	}
	return res
}

// Get read and write endpoints
func (cov *EpCover) GetEndpointCount() (read int, write int) {
	c := *cov
	if c == nil {
		return 0, 0
	}

	for _, epMap := range c {
		read += epMap[MAGIC_READ_ENTRY]
		write += epMap[MAGIC_WRITE_ENTRY]
	}

	return
}

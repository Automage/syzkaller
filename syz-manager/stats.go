// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"
	"sync/atomic"
)

type Stat uint64

type Stats struct {
	crashes           Stat
	crashTypes        Stat
	crashSuppressed   Stat
	vmRestarts        Stat
	newInputs         Stat
	rotatedInputs     Stat
	execTotal         Stat
	hubSendProgAdd    Stat
	hubSendProgDel    Stat
	hubSendRepro      Stat
	hubRecvProg       Stat
	hubRecvProgDrop   Stat
	hubRecvRepro      Stat
	hubRecvReproDrop  Stat
	corpusCover       Stat
	corpusSignal      Stat
	corpusMemCover    Stat
	corpusDuCover     Stat
	edgeMetric        Stat
	memMetric         Stat
	bothMetric        Stat
	corpusOgMemCover  Stat
	corpusComMemCover Stat
	maxSignal         Stat

	mu         sync.Mutex
	namedStats map[string]uint64
	haveHub    bool
}

func (stats *Stats) all() map[string]uint64 {
	m := map[string]uint64{
		"crashes":        stats.crashes.get(),
		"crash types":    stats.crashTypes.get(),
		"suppressed":     stats.crashSuppressed.get(),
		"vm restarts":    stats.vmRestarts.get(),
		"new inputs":     stats.newInputs.get(),
		"rotated inputs": stats.rotatedInputs.get(),
		"exec total":     stats.execTotal.get(),
		"cover":          stats.corpusCover.get(),
		// Pranav: added mem cover, du cover, og mem, com mem cover
		"mem cover":              stats.corpusMemCover.get(),
		"du pair cover":          stats.corpusDuCover.get(),
		"edge metric inputs":     stats.edgeMetric.get(),
		"mem metric inputs":      stats.memMetric.get(),
		"both metric inputs":     stats.bothMetric.get(),
		"og mem cover":           stats.corpusOgMemCover.get(),
		"communicated mem cover": stats.corpusComMemCover.get(),
		"signal":                 stats.corpusSignal.get(),
		"max signal":             stats.maxSignal.get(),
	}
	if stats.haveHub {
		m["hub: send prog add"] = stats.hubSendProgAdd.get()
		m["hub: send prog del"] = stats.hubSendProgDel.get()
		m["hub: send repro"] = stats.hubSendRepro.get()
		m["hub: recv prog"] = stats.hubRecvProg.get()
		m["hub: recv prog drop"] = stats.hubRecvProgDrop.get()
		m["hub: recv repro"] = stats.hubRecvRepro.get()
		m["hub: recv repro drop"] = stats.hubRecvReproDrop.get()
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	for k, v := range stats.namedStats {
		m[k] = v
	}
	return m
}

func (stats *Stats) mergeNamed(named map[string]uint64) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.namedStats == nil {
		stats.namedStats = make(map[string]uint64)
	}
	for k, v := range named {
		switch k {
		case "exec total":
			stats.execTotal.add(int(v))
		default:
			stats.namedStats[k] += v
		}
	}
}

func (s *Stat) get() uint64 {
	return atomic.LoadUint64((*uint64)(s))
}

func (s *Stat) inc() {
	s.add(1)
}

func (s *Stat) add(v int) {
	atomic.AddUint64((*uint64)(s), uint64(v))
}

func (s *Stat) set(v int) {
	atomic.StoreUint64((*uint64)(s), uint64(v))
}

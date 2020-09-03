// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				// Pranav: execOpts -> execOptsCover to compute DuPairs
				proc.execute(proc.execOptsCover, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

// Pranav: sending memory coverage back to manager
func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)

	// Pranav: compute mem cov or du pairs for this call
	//evalDu := 0 // 0 - edge, 1 - memcover, 2 - du cover

	var inputMemCover cover.MemCover
	// inputMemCover.Merge(item.info.MemCover)
	// inputMemCoverSerialized := inputMemCover.Serialize()
	// mCovDiff := proc.fuzzer.corpusMemCoverDiff(inputMemCoverSerialized)

	var inputDuCover cover.DuCover
	// total, unique := inputDuCover.ComputeDuCov(item.info.MemCover, item.info.IpCover, item.info.TypeCover)
	// duDiff := proc.fuzzer.corpusDuCoverDiff(inputDuCover)

	// if evalDu == 2 { // Du cov
	// 	log.Logf(3, "====== DU Pairs: total %v unique %v PRE-INTERSECT duDiff: %v fuzzerCorpus: %v", total, unique, duDiff, len(proc.fuzzer.corpusDuCover))
	// 	if duDiff < 0 {
	// 		log.Logf(3, "ASSERT FAILED: DUDIFF < 0 : %v", duDiff)
	// 	} else if duDiff == 0 {
	// 		log.Logf(3, "3141: Rejecting call due to no ducover...")
	// 	}

	// 	// Pranav - Make sure call has new ducover as well
	// 	if newSignal.Empty() || duDiff == 0 {
	// 		return
	// 	}
	// } else if evalDu == 1 { // Mem cov
	// 	log.Logf(3, "====== Mem Cov: total %v unique %v PRE-INTERSECT mCovDiff: %v fuzzerCorpus: %v", len(item.info.MemCover), len(inputMemCover), mCovDiff, len(proc.fuzzer.corpusMemCover))
	// 	if mCovDiff < 0 {
	// 		log.Logf(3, "ASSERT FAILED: MCOVDIFF < 0 : %v", duDiff)
	// 	} else if mCovDiff == 0 {
	// 		log.Logf(3, "3141: Rejecting call due to no mem cov...")
	// 	}

	// 	if newSignal.Empty() || mCovDiff == 0 {
	// 		return
	// 	}
	// } else { // OG Syzkaller
	inputMemCover.ComputeHashCov(item.info.MemCover, item.info.IpCover, item.info.TypeCover)
	inputMemCoverSerialized := inputMemCover.Serialize()
	mCovDiff := proc.fuzzer.corpusMemCoverDiff(inputMemCoverSerialized)

	if mCovDiff == 0 {
		log.Logf(3, "Khushboo : Call rejected due")
	}

	covMetric := 0 // 0 - added by edge, 1 - added by mem, 2 - added by both
	if newSignal.Empty() && mCovDiff == 0 {
		return
	} else if newSignal.Empty() {
		covMetric = 1
	} else if mCovDiff == 0 {
		covMetric = 0
	} else {
		covMetric = 2
	}
	//}

	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	var intersectMemCover cover.MemCover
	//var intersectDuCover cover.DuCover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		// Pranav: return memCover too
		thisSignal, thisCover, thisMemCover, thisIpCover, thisTypeCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)

		// Pranav : compute memcover, Du Pairs and calculate intersection
		// if evalDu { // Du cov
		// 	if i == 0 {
		// 		duTotal, duUnique := intersectDuCover.ComputeDuCov(thisMemCover, thisIpCover, thisTypeCover)
		// 		log.Logf(3, "====== DU Pairs: total %v unique %v addrs %v intersect %v (first compute)", duTotal, duUnique, len(thisMemCover), len(intersectDuCover))
		// 	} else {
		// 		var currDuCover cover.DuCover
		// 		duTotal, duUnique := currDuCover.ComputeDuCov(thisMemCover, thisIpCover, thisTypeCover)
		// 		intersectDuCover = intersectDuCover.Intersection(currDuCover)
		// 		log.Logf(3, "====== DU Pairs: total %v unique %v addrs %v intersect %v", duTotal, duUnique, len(thisMemCover), len(intersectDuCover))
		// 	}

		// 	if intersectDuCover.Empty() {
		// 		log.Logf(3, "3141: Rejecting call due to empty du intersect...")
		// 	}
		// } else { // Mem cov
		var currMemCover cover.MemCover
		total := currMemCover.ComputeHashCov(thisMemCover, thisIpCover, thisTypeCover)
		if i == 0 {
			//intersectMemCover.Merge(thisMemCover)
			intersectMemCover.Merge(currMemCover.Serialize())
			log.Logf(3, "====== Mem Cov: total %v intersect %v (first compute)", total, len(intersectMemCover))
		} else {
			intersectMemCover = intersectMemCover.Intersection(currMemCover.Serialize())
			log.Logf(3, "====== Mem Cov: total %v intersect %v", total, len(intersectMemCover))
		}

		if intersectMemCover.Empty() {
			log.Logf(3, "3141: Rejecting call due to empty mem intersect...")
		}
		// }

		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		//if newSignal.Empty() && item.flags&ProgMinimized == 0 {
		// Pranav: Check if ducov intersect is also empty (probably never the case)
		// TODO: maybe less than a threshold?
		//if (newSignal.Empty() && item.flags&ProgMinimized == 0) || intersectMemCover.Empty() {
		if (newSignal.Empty() && item.flags&ProgMinimized == 0) || intersectMemCover.Empty() {
			// 3141 - If no intersection in signal between calls, discard as it is flaky/no real coverage
			return
		}

		inputCover.Merge(thisCover)
		inputMemCover.Merge(currMemCover)
	}
	if item.flags&ProgMinimized == 0 {
		// 3141 - Minimize prog cuts all calls that do not contribute to signal
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _, _, _, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:     callName,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		MemCover: inputMemCover.Serialize(),
		DuCover:  inputDuCover.Serialize(),
		Metric:   covMetric,
	})

	// Pranav: send ducov map to fuzzer corpus as well
	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig, inputDuCover, inputMemCoverSerialized)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

// Pranav: Changes made to return MemCover too
func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32, []uint64, []uint64, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover, inf.MemCover, inf.IpCover, inf.TypeCover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		// Pranav: execOpts -> execOptscover for du evaluation
		proc.execute(proc.execOptsCover, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	// 3141 - Possible throw away of calls
	// TODO: modify
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	log.Logf(1, "$$$ calls=%v", len(calls))
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	for _, call := range p.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v", call.Meta.Name)
			panic("disabled syscall")
		}
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}

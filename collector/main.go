package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/table"
	"github.com/liamg/tml"
)

const (
	ProcRootDir     = "/proc"
	ProcCPUInfoName = "cpuinfo"
	ProcStatName    = "stat"

	SysRootDir          = "/sys"
	SysCPUSMTActivePath = "devices/system/cpu/smt/active"
)

type CPUInfo struct {
	CPUId    int32
	CoreId   int32
	SocketId int32
	NodeId   int32
}

type CPUTime struct {
	CPUId       int32
	CollectTime time.Time
	User        uint64
	Nice        uint64
	Sys         uint64
	Idle        uint64
	IOWait      uint64
	IRQ         uint64
	SoftIRQ     uint64
	Steal       uint64
	Guest       uint64
	GuestNice   uint64
}

func (t *CPUTime) TotalIdleTime() uint64 {
	return t.Idle + t.IOWait
}

func (t *CPUTime) TotalSystemTime() uint64 {
	return t.Sys + t.IRQ + t.SoftIRQ
}

func (t *CPUTime) TotalVirtualTime() uint64 {
	return t.Guest + t.GuestNice
}

func (t *CPUTime) TotalTime() uint64 {
	return t.User + t.Nice + t.TotalSystemTime() + t.TotalIdleTime() + t.Steal + t.TotalVirtualTime()
}

type CPUTimePeriod struct {
	CPUId             int32
	UserPeriod        uint64
	NicePeriod        uint64
	SysPeriod         uint64
	TotalSystemPeriod uint64
	IdlePeriod        uint64
	TotalIdlePeriod   uint64
	IOWaitPeriod      uint64
	IRQPeriod         uint64
	SoftIRQPeriod     uint64
	StealPeriod       uint64
	GuestPeriod       uint64
	TotalPeriod       uint64
}

func SaturatedSub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}

	return 0
}

func NewCPUTimePeriod(t1, t2 *CPUTime) (*CPUTimePeriod, error) {
	if t1.CPUId != t2.CPUId {
		return nil, fmt.Errorf("CPU IDs don't match: %d != %d", t1.CPUId, t2.CPUId)
	}

	if t2.CollectTime.Before(t1.CollectTime) {
		return nil, fmt.Errorf("collect time is not in order: %v > %v", t1.CollectTime, t2.CollectTime)
	}

	return &CPUTimePeriod{
		CPUId:             t1.CPUId,
		UserPeriod:        SaturatedSub(t2.User, t1.User),
		NicePeriod:        SaturatedSub(t2.Nice, t1.Nice),
		SysPeriod:         SaturatedSub(t2.Sys, t1.Sys),
		TotalSystemPeriod: SaturatedSub(t2.TotalSystemTime(), t1.TotalSystemTime()),
		IdlePeriod:        SaturatedSub(t2.Idle, t1.Idle),
		TotalIdlePeriod:   SaturatedSub(t2.TotalIdleTime(), t1.TotalIdleTime()),
		IOWaitPeriod:      SaturatedSub(t2.IOWait, t1.IOWait),
		IRQPeriod:         SaturatedSub(t2.IRQ, t1.IRQ),
		SoftIRQPeriod:     SaturatedSub(t2.SoftIRQ, t1.SoftIRQ),
		StealPeriod:       SaturatedSub(t2.Steal, t1.Steal),
		GuestPeriod:       SaturatedSub(t2.Guest, t1.Guest),
		TotalPeriod:       SaturatedSub(t2.TotalTime(), t1.TotalTime()),
	}, nil
}

func GetCPUInfoPath() string {
	return filepath.Join(ProcRootDir, ProcCPUInfoName)
}

func GetProcStatPath() string {
	return filepath.Join(ProcRootDir, ProcStatName)
}

func GetSysCPUSMTActivePath() string {
	return filepath.Join(SysRootDir, SysCPUSMTActivePath)
}

func GetCPUModel() (string, error) {
	cpuInfoPath := GetCPUInfoPath()
	f, err := os.Open(cpuInfoPath)
	if err != nil {
		return "unknown", fmt.Errorf("failed to open %s: %v", cpuInfoPath, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if err = s.Err(); err != nil {
			return "unknown", fmt.Errorf("failed to read %s: %v", cpuInfoPath, err)
		}

		line := s.Text()
		if strings.Contains(line, "model name") || strings.Contains(line, "Model Name") {
			attrs := strings.Split(line, ":")
			if len(attrs) >= 2 {
				return strings.TrimSpace(attrs[1]), nil
			}
		}
	}

	return "unknown", fmt.Errorf("failed to find model name in %s", cpuInfoPath)
}

func IsSMTEnabled() (bool, error) {
	smtActivePath := GetSysCPUSMTActivePath()
	out, err := os.ReadFile(smtActivePath)
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %v", smtActivePath, err)
	}

	return strings.TrimSpace(string(out)) == "1", nil
}

func doLsCPU() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	executable, err := exec.LookPath("lscpu")
	if err != nil {
		return "", fmt.Errorf("failed to find lscpu: %v", err)
	}

	out, err := exec.CommandContext(ctx, executable, "-e=CPU,NODE,SOCKET,CORE").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run lscpu: %v", err)
	}

	return string(out), nil
}

func getCPUInfos() ([]CPUInfo, error) {
	lsCPUStr, err := doLsCPU()
	if err != nil {
		return nil, err
	}

	/*
		# lscpu -e=CPU,NODE,SOCKET,CORE
		Format:
		CPU NODE SOCKET CORE
		0   0    0      0
		1   0    0      1
	*/

	var cpuInfos []CPUInfo
	for _, line := range strings.Split(lsCPUStr, "\n") {
		items := strings.Fields(line)
		if len(items) < 4 {
			continue
		}

		cpuId, err := strconv.ParseInt(items[0], 10, 32)
		if err != nil {
			continue
		}

		nodeId, err := strconv.ParseInt(items[1], 10, 32)
		if err != nil {
			continue
		}

		socketId, err := strconv.ParseInt(items[2], 10, 32)
		if err != nil {
			continue
		}

		coreId, err := strconv.ParseInt(items[3], 10, 32)
		if err != nil {
			continue
		}

		info := CPUInfo{
			CPUId:    int32(cpuId),
			CoreId:   int32(coreId),
			SocketId: int32(socketId),
			NodeId:   int32(nodeId),
		}

		cpuInfos = append(cpuInfos, info)
	}

	if len(cpuInfos) == 0 {
		return nil, fmt.Errorf("failed to get CPU infos")
	}

	sort.Slice(cpuInfos, func(i, j int) bool {
		a, b := cpuInfos[i], cpuInfos[j]
		if a.NodeId != b.NodeId {
			return a.NodeId < b.NodeId
		}

		if a.SocketId != b.SocketId {
			return a.SocketId < b.SocketId
		}

		if a.CoreId != b.CoreId {
			return a.CoreId < b.CoreId
		}

		return a.CPUId < b.CPUId
	})

	return cpuInfos, nil
}

func getCPUTimes() ([]CPUTime, error) {
	procStatPath := GetProcStatPath()
	f, err := os.Open(procStatPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", procStatPath, err)
	}
	defer f.Close()

	now := time.Now()

	s := bufio.NewScanner(f)
	var cpuTimes []CPUTime

	for s.Scan() {
		if err = s.Err(); err != nil {
			return nil, fmt.Errorf("failed to read %s: %v", procStatPath, err)
		}

		line := s.Text()
		items := strings.Fields(line)

		if len(items) < 11 {
			continue
		}

		if !strings.HasPrefix(items[0], "cpu") {
			continue
		}

		// Ignore total CPU time
		cpuId, err := strconv.ParseInt(strings.TrimPrefix(items[0], "cpu"), 10, 32)
		if err != nil {
			continue
		}

		user, err := strconv.ParseUint(items[1], 10, 64)
		if err != nil {
			continue
		}

		nice, err := strconv.ParseUint(items[2], 10, 64)
		if err != nil {
			continue
		}

		sys, err := strconv.ParseUint(items[3], 10, 64)
		if err != nil {
			continue
		}

		idle, err := strconv.ParseUint(items[4], 10, 64)
		if err != nil {
			continue
		}

		iowait, err := strconv.ParseUint(items[5], 10, 64)
		if err != nil {
			continue
		}

		irq, err := strconv.ParseUint(items[6], 10, 64)
		if err != nil {
			continue
		}

		softIRQ, err := strconv.ParseUint(items[7], 10, 64)
		if err != nil {
			continue
		}

		steal, err := strconv.ParseUint(items[8], 10, 64)
		if err != nil {
			continue
		}

		guest, err := strconv.ParseUint(items[9], 10, 64)
		if err != nil {
			continue
		}

		guestNice, err := strconv.ParseUint(items[10], 10, 64)
		if err != nil {
			continue
		}

		// Guest time is already accounted in usertime
		user -= guest
		nice -= guestNice

		time := CPUTime{
			CPUId:       int32(cpuId),
			CollectTime: now,
			User:        user,
			Nice:        nice,
			Sys:         sys,
			Idle:        idle,
			IOWait:      iowait,
			IRQ:         irq,
			SoftIRQ:     softIRQ,
			Steal:       steal,
			Guest:       guest,
			GuestNice:   guestNice,
		}

		cpuTimes = append(cpuTimes, time)
	}

	return cpuTimes, nil
}

// The state of the art following top, htop, bottom, btop, etc
func DoAverageCPUUsage(cpuTimePeriods map[int32]*CPUTimePeriod) (float64, error) {
	var totalPeriod uint64
	var totalIdlePeriod uint64
	for _, period := range cpuTimePeriods {
		totalPeriod += period.TotalPeriod
		totalIdlePeriod += period.TotalIdlePeriod
	}

	if totalPeriod == 0 {
		return 0.0, fmt.Errorf("total period is zero")
	}

	cpuUtilization := 100.0 * (1 - float64(totalIdlePeriod)/float64(totalPeriod))

	return cpuUtilization, nil
}

func DoAdjustedCPUUsage(cpuToCores map[int32]int32, coreToCpus map[int32][]int32, cpuTimePeriods map[int32]*CPUTimePeriod) (float64, error) {
	var totalPeriod uint64
	var totalIdlePeriod uint64

	for _, cpuIds := range coreToCpus {
		ht0 := cpuTimePeriods[cpuIds[0]]
		ht1 := cpuTimePeriods[cpuIds[1]]

		period := max(ht0.TotalPeriod, ht1.TotalPeriod)
		idlePeriod := min(ht0.TotalIdlePeriod, ht1.TotalIdlePeriod)

		totalPeriod += period
		totalIdlePeriod += idlePeriod
	}

	if totalPeriod == 0 {
		return 0.0, fmt.Errorf("total period is zero")
	}

	cpuUtilization := 100.0 * (1 - float64(totalIdlePeriod)/float64(totalPeriod))

	return cpuUtilization, nil
}

func DoCollectorLoop(cpuToCore map[int32]int32, coreToCpus map[int32][]int32) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	tbl := table.New(os.Stdout)
	tbl.SetBorders(true)
	tbl.SetHeaderStyle(table.StyleBold)
	tbl.SetLineStyle(table.StyleBlue)
	tbl.SetDividers(table.UnicodeRoundedDividers)

	tbl.SetHeaders("Time", "Avg CPU Usage", "Adjusted CPU Usage", "Avg Remaining CPU", "RCPU", "Difference")
	tbl.SetAlignment(table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter)

	var prevCPUTimes []CPUTime
	for range ticker.C {
		cpuTimes, err := getCPUTimes()
		if err != nil {
			log.Fatalf("failed to get CPU times: %v", err)
			continue
		}

		if len(prevCPUTimes) == 0 {
			prevCPUTimes = cpuTimes
			continue
		}

		cpuTimePeriods := make(map[int32]*CPUTimePeriod)
		for i, t1 := range prevCPUTimes {
			t2 := cpuTimes[i]

			period, err := NewCPUTimePeriod(&t1, &t2)
			if err != nil {
				log.Fatalf("failed to create CPU time period: %v", err)
			}

			cpuTimePeriods[t1.CPUId] = period
		}

		avgCPUUsage, err := DoAverageCPUUsage(cpuTimePeriods)
		if err != nil {
			log.Fatalf("failed to calculate average CPU usage: %v", err)
		}
		adjustedCPUUsage, err := DoAdjustedCPUUsage(cpuToCore, coreToCpus, cpuTimePeriods)
		if err != nil {
			log.Fatalf("failed to calculate adjusted CPU usage: %v", err)
		}

		avgRemainingCPUUsage := 100.0 - avgCPUUsage
		adjustedRemainingCPUUsage := 100.0 - adjustedCPUUsage

		diffUsage := avgRemainingCPUUsage - adjustedRemainingCPUUsage

		now := cpuTimes[0].CollectTime

		tbl.AddRow(
			now.Format("15:04:05"),
			tml.Sprintf("<yellow>%.2f%%</yellow>", avgCPUUsage),
			tml.Sprintf("<green>%.2f%%</green>", adjustedCPUUsage),
			tml.Sprintf("<yellow>%.2f%%</yellow>", avgRemainingCPUUsage),
			tml.Sprintf("<green>%.2f%%</green>", adjustedRemainingCPUUsage),
			tml.Sprintf("<bold><red>%.2f%%</red></bold>", diffUsage),
		)

		// Clear screen
		fmt.Print("\033[H\033[2J")
		tbl.Render()

		prevCPUTimes = cpuTimes
	}
}

func main() {
	model, err := GetCPUModel()
	if err != nil {
		log.Fatalf("failed to get CPU model: %v", err)
	}

	// Check if Intel CPU
	if !strings.Contains(model, "Intel") {
		log.Fatalf("unsupported CPU model: %s", model)
	}

	if smt, err := IsSMTEnabled(); err != nil {
		log.Fatalf("failed to check if SMT is enabled: %v", err)
	} else if !smt {
		log.Fatalf("SMT is not enabled")
	}

	log.Printf("CPU model: %s\n", model)
	log.Printf("SMT is enabled\n")

	cpuInfos, err := getCPUInfos()
	if err != nil {
		log.Fatalf("failed to get CPU infos: %v", err)
	}

	log.Printf("CPU infos:\n")
	for _, info := range cpuInfos {
		log.Printf("  CPU %d, Core %d, Socket %d, Node %d\n", info.CPUId, info.CoreId, info.SocketId, info.NodeId)
	}

	cpuToCore := make(map[int32]int32)
	for _, info := range cpuInfos {
		cpuToCore[info.CPUId] = info.CoreId
	}

	coreToCpus := make(map[int32][]int32)
	for _, info := range cpuInfos {
		coreToCpus[info.CoreId] = append(coreToCpus[info.CoreId], info.CPUId)
	}

	for coreId, cpuIds := range coreToCpus {
		if len(cpuIds) != 2 {
			log.Fatalf("core %d has %d CPUs, expected 2", coreId, len(cpuIds))
		}
	}

	log.Printf("Collector is running\n")

	DoCollectorLoop(cpuToCore, coreToCpus)
}

// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type hostMetricsSnapshot struct {
	cpuTotal, cpuIdle  uint64
	memTotal, memAvail uint64
	cpuOK, memOK       bool
}

func captureHostMetrics() hostMetricsSnapshot {
	var snapshot hostMetricsSnapshot
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
		if len(fields) >= 5 && fields[0] == "cpu" {
			valid := true
			var values []uint64
			for _, field := range fields[1:] {
				value, parseErr := strconv.ParseUint(field, 10, 64)
				if parseErr != nil {
					valid = false
					break
				}
				values = append(values, value)
			}
			if valid && len(values) >= 4 {
				for _, value := range values {
					snapshot.cpuTotal += value
				}
				snapshot.cpuIdle = values[3]
				if len(values) > 4 {
					snapshot.cpuIdle += values[4]
				}
				snapshot.cpuOK = true
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalOK, availableOK bool
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				continue
			}
			switch strings.TrimSuffix(fields[0], ":") {
			case "MemTotal":
				snapshot.memTotal, totalOK = value, true
			case "MemAvailable":
				snapshot.memAvail, availableOK = value, true
			}
		}
		snapshot.memOK = totalOK && availableOK
	}
	return snapshot
}

func hostPlatformInfo() (kernel, cpuModel string) {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.SplitN(line, ":", 2)
			if len(fields) != 2 {
				continue
			}
			key := strings.TrimSpace(fields[0])
			if key == "model name" || key == "Hardware" || key == "Processor" {
				cpuModel = strings.TrimSpace(fields[1])
				break
			}
		}
	}
	return kernel, cpuModel
}

func simnodeCPUTimeMS(runDir, program string) (uint64, bool) {
	clockOutput, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return 0, false
	}
	ticksPerSecond, err := strconv.ParseUint(strings.TrimSpace(string(clockOutput)), 10, 64)
	if err != nil || ticksPerSecond == 0 {
		return 0, false
	}
	files, err := filepath.Glob(filepath.Join(runDir, "pids", "*.json"))
	if err != nil {
		return 0, false
	}
	var totalTicks uint64
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var process processRecord
		if json.Unmarshal(data, &process) != nil || process.Program != program || process.PID <= 1 {
			continue
		}
		stat, statErr := os.ReadFile(filepath.Join("/proc", fmt.Sprint(process.PID), "stat"))
		if statErr != nil {
			continue
		}
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(stat)[end+1:])
		if len(fields) <= 12 {
			continue
		}
		userTicks, userErr := strconv.ParseUint(fields[11], 10, 64)
		systemTicks, systemErr := strconv.ParseUint(fields[12], 10, 64)
		if userErr == nil && systemErr == nil {
			totalTicks += userTicks + systemTicks
		}
	}
	return totalTicks * 1000 / ticksPerSecond, true
}

func summarizeHostMetrics(start, end hostMetricsSnapshot) HostResourceReport {
	report := HostResourceReport{
		StartMemoryTotalKB: start.memTotal, StartMemoryAvailableKB: start.memAvail,
		EndMemoryTotalKB: end.memTotal, EndMemoryAvailableKB: end.memAvail,
		CPUStatsAvailable:    start.cpuOK && end.cpuOK,
		MemoryStatsAvailable: start.memOK && end.memOK,
	}
	if report.CPUStatsAvailable {
		totalDelta := end.cpuTotal - start.cpuTotal
		idleDelta := end.cpuIdle - start.cpuIdle
		if totalDelta > 0 && idleDelta <= totalDelta {
			report.HostCPUUtilizationPct = float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
		}
	}
	return report
}

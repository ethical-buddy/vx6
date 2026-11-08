// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type processRecord struct {
	PID        int    `json:"pid"`
	Namespace  string `json:"namespace"`
	Program    string `json:"program"`
	NetNSInode uint64 `json:"netns_inode"`
}

func recordProcess(dir, namespace, program string, cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || namespace == "" || program == "" {
		return errors.New("cannot record an unstarted simulation process")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inode, err := processNetNSInode(cmd.Process.Pid)
		if err == nil {
			args, argErr := processArgs(cmd.Process.Pid)
			if argErr == nil && hasProgram(args, program) {
				record := processRecord{PID: cmd.Process.Pid, Namespace: namespace,
					Program: filepath.Base(program), NetNSInode: inode}
				return writeProcessRecord(dir, record)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("process %s did not enter namespace %s", program, namespace)
}

func writeProcessRecord(dir string, record processRecord) error {
	if record.PID <= 1 || record.Program == "" || record.Namespace == "" || record.NetNSInode == 0 {
		return errors.New("incomplete process record")
	}
	pidDir := filepath.Join(dir, "pids")
	if err := os.MkdirAll(pidDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := filepath.Join(pidDir, record.Namespace+"-"+record.Program+".json")
	return os.WriteFile(path, data, 0o600)
}

func processArgs(pid int) ([]string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(data), "\x00")
	var args []string
	for _, part := range parts {
		if part != "" {
			args = append(args, part)
		}
	}
	return args, nil
}

func hasProgram(args []string, program string) bool {
	want := filepath.Base(program)
	for _, arg := range args {
		if filepath.Base(arg) == want {
			return true
		}
	}
	return false
}

func processNetNSInode(pid int) (uint64, error) {
	info, err := os.Stat(filepath.Join("/proc", fmt.Sprint(pid), "ns/net"))
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot inspect process network namespace")
	}
	return stat.Ino, nil
}

func stopChild(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return nil
			}
		}
		return err
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return nil
	}
}

// stopRecordedProcess only signals a process if both its executable and its
// network-namespace inode match the persisted record. That prevents a stale
// PID file from killing an unrelated process after PID reuse.
func stopRecordedProcess(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var record processRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("read process record %s: %w", path, err)
	}
	pid, err := parsePID(fmt.Sprint(record.PID))
	if err != nil || record.Program == "" || record.NetNSInode == 0 {
		return fmt.Errorf("invalid process record %s", path)
	}
	inode, err := processNetNSInode(pid)
	if errors.Is(err, os.ErrNotExist) {
		return os.Remove(path)
	}
	if err != nil {
		return fmt.Errorf("inspect recorded process %d: %w", pid, err)
	}
	args, err := processArgs(pid)
	if errors.Is(err, os.ErrNotExist) {
		return os.Remove(path)
	}
	if err != nil {
		return err
	}
	if inode != record.NetNSInode || !hasProgram(args, record.Program) {
		// The original process is gone and this PID has been reused or exec'd;
		// leave the unrelated process alone and discard the stale record.
		return os.Remove(path)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if processStopped(pid) {
			return os.Remove(path)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for i := 0; i < 20; i++ {
		if processStopped(pid) {
			return os.Remove(path)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("PID %d did not stop", pid)
}

func stopPersistedProcesses(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	var failures []error
	for _, path := range files {
		if err := stopRecordedProcess(path); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func processStopped(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	line := string(data)
	end := strings.LastIndexByte(line, ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(line[end+1:])
	return len(fields) > 0 && fields[0] == "Z"
}

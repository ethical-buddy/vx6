package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func (s *state) runDeviceTest(cfg mediaConfig) (string, error) {
	ffmpegPath := strings.TrimSpace(cfg.FFmpegPath)
	var err error
	if ffmpegPath == "" {
		ffmpegPath, err = exec.LookPath("ffmpeg")
	} else {
		_, err = exec.LookPath(ffmpegPath)
	}
	if err != nil {
		return "", fmt.Errorf("ffmpeg not found: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	videoArgs, audioArgs := buildDeviceTestArgs(cfg)
	videoOK, _ := runFFmpegProbe(ctx, ffmpegPath, videoArgs)
	audioOK, audioOut := runFFmpegProbe(ctx, ffmpegPath, audioArgs)

	micLevel := extractMicLevel(audioOut)
	if micLevel == "" {
		micLevel = "unavailable"
	}

	report := fmt.Sprintf("Video: %s\nAudio: %s\nMic level: %s", passFail(videoOK), passFail(audioOK), micLevel)
	if !videoOK && !audioOK {
		return report, fmt.Errorf("camera and mic probe failed")
	}
	return report, nil
}

func buildDeviceTestArgs(cfg mediaConfig) ([]string, []string) {
	switch runtime.GOOS {
	case "linux":
		v := cfg.VideoDevice
		if strings.TrimSpace(v) == "" {
			v = "/dev/video0"
		}
		a := cfg.AudioDevice
		if strings.TrimSpace(a) == "" {
			a = "default"
		}
		return []string{"-hide_banner", "-loglevel", "info", "-f", "v4l2", "-i", v, "-t", "3", "-f", "null", "-"},
			[]string{"-hide_banner", "-loglevel", "info", "-f", "pulse", "-i", a, "-t", "3", "-af", "volumedetect", "-f", "null", "-"}
	case "windows":
		v := cfg.VideoDevice
		if strings.TrimSpace(v) == "" {
			v = "default"
		}
		a := cfg.AudioDevice
		if strings.TrimSpace(a) == "" {
			a = "default"
		}
		return []string{"-hide_banner", "-loglevel", "info", "-f", "dshow", "-i", "video=" + v, "-t", "3", "-f", "null", "-"},
			[]string{"-hide_banner", "-loglevel", "info", "-f", "dshow", "-i", "audio=" + a, "-t", "3", "-af", "volumedetect", "-f", "null", "-"}
	case "darwin":
		v := cfg.VideoDevice
		if strings.TrimSpace(v) == "" {
			v = "0:0"
		}
		return []string{"-hide_banner", "-loglevel", "info", "-f", "avfoundation", "-i", v, "-t", "3", "-f", "null", "-"},
			[]string{"-hide_banner", "-loglevel", "info", "-f", "avfoundation", "-i", v, "-t", "3", "-af", "volumedetect", "-f", "null", "-"}
	default:
		return []string{"-version"}, []string{"-version"}
	}
}

func runFFmpegProbe(ctx context.Context, ffmpegPath string, args []string) (bool, string) {
	cmd := exec.CommandContext(ctx, ffmpegPath, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		return false, out
	}
	return true, out
}

func extractMicLevel(out string) string {
	lines := strings.Split(out, "\n")
	for _, ln := range lines {
		l := strings.TrimSpace(strings.ToLower(ln))
		if strings.Contains(l, "mean_volume:") || strings.Contains(l, "max_volume:") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

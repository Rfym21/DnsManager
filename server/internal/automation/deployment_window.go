package automation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type DeploymentWindow struct {
	Enabled  bool   `json:"enabled"`
	Timezone string `json:"timezone"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Weekdays []int  `json:"weekdays"`
}

type DeploymentRetryPolicy struct {
	MaxAttempts  int `json:"max_attempts"`
	DelaySeconds int `json:"delay_seconds"`
}

type DeferredError struct {
	Err   error
	Until time.Time
}

func (e *DeferredError) Error() string { return e.Err.Error() }
func (e *DeferredError) Unwrap() error { return e.Err }

func deploymentClock(value string) (int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, errors.New("部署窗口时间须为 HH:mm")
	}
	hour, e1 := strconv.Atoi(value[:2])
	minute, e2 := strconv.Atoi(value[3:])
	if e1 != nil || e2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 || strings.ContainsAny(value, "+- ") {
		return 0, errors.New("部署窗口时间须为 HH:mm")
	}
	return hour*60 + minute, nil
}

func ValidateDeploymentWindow(window DeploymentWindow) error {
	if !window.Enabled {
		return nil
	}
	if _, err := time.LoadLocation(window.Timezone); window.Timezone == "" || err != nil {
		return errors.New("部署窗口需要有效时区")
	}
	start, err := deploymentClock(window.Start)
	if err != nil {
		return err
	}
	end, err := deploymentClock(window.End)
	if err != nil {
		return err
	}
	if start == end {
		return errors.New("部署窗口开始与结束时间不能相同")
	}
	seen := map[int]bool{}
	if len(window.Weekdays) == 0 || len(window.Weekdays) > 7 {
		return errors.New("部署窗口须至少选择一个星期")
	}
	for _, day := range window.Weekdays {
		if day < 0 || day > 6 || seen[day] {
			return errors.New("部署窗口星期须为不重复的 0 至 6")
		}
		seen[day] = true
	}
	return nil
}

func NormalizeDeploymentRetryPolicy(policy DeploymentRetryPolicy) (DeploymentRetryPolicy, error) {
	if policy.MaxAttempts == 0 {
		policy.MaxAttempts = 3
	}
	if policy.DelaySeconds == 0 {
		policy.DelaySeconds = 60
	}
	if policy.MaxAttempts < 1 || policy.MaxAttempts > 10 || policy.DelaySeconds < 5 || policy.DelaySeconds > 86400 {
		return policy, errors.New("部署重试次数须为1至10，间隔须为5至86400秒")
	}
	return policy, nil
}

// Cross-midnight windows belong to their starting weekday. Time boundaries
// are inclusive at the start and exclusive at the end, in the configured zone.
func deploymentWindowNext(window DeploymentWindow, now time.Time) (time.Time, error) {
	if err := ValidateDeploymentWindow(window); err != nil {
		return time.Time{}, err
	}
	if !window.Enabled {
		return now, nil
	}
	loc, _ := time.LoadLocation(window.Timezone)
	local := now.In(loc)
	start, _ := deploymentClock(window.Start)
	end, _ := deploymentClock(window.End)
	allowed := map[int]bool{}
	for _, day := range window.Weekdays {
		allowed[day] = true
	}
	date := time.Date(local.Year(), local.Month(), local.Day(), 12, 0, 0, 0, loc)
	for offset := -1; offset <= 8; offset++ {
		day := date.AddDate(0, 0, offset)
		if !allowed[int(day.Weekday())] {
			continue
		}
		from := time.Date(day.Year(), day.Month(), day.Day(), start/60, start%60, 0, 0, loc)
		endDay := day
		if end < start {
			endDay = day.AddDate(0, 0, 1)
		}
		until := time.Date(endDay.Year(), endDay.Month(), endDay.Day(), end/60, end%60, 0, 0, loc)
		// DST can normalize a nonexistent clock hour. Refuse an inverted
		// window and continue to the next matching day.
		if !until.After(from) {
			continue
		}
		if !now.Before(from) && now.Before(until) {
			return now, nil
		}
		if from.After(now) {
			return from, nil
		}
	}
	return time.Time{}, fmt.Errorf("未来8天没有可用部署窗口")
}

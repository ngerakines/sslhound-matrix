package check

import "time"

// CollectedInfo is key-value information used to represent facts collected
// from an endpoint check execution.
type CollectedInfo struct {
	Name     string
	Value    string
	Duration time.Duration
}

// Collector is a channel that collected information is published to.
type Collector chan CollectedInfo


package main

import "time"

// systemClock implements core.Clock using the real wall clock.
// Time is I/O; injecting the clock keeps the core deterministic.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

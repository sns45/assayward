package core

import "time"

type Clock interface{ Now() time.Time }

// FixedClock makes decisions deterministic and testable.
type FixedClock struct{ T time.Time }

func (c FixedClock) Now() time.Time { return c.T }

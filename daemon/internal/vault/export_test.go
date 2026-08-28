package vault

import "time"

// SetPurgeGraceForTest lets the black-box tests sweep entries they have just
// created, without sleeping through the window that exists to protect a
// discovery run mid-flight.
//
// It returns a restore func rather than mutating for the whole binary: these
// tests run in the same process, and a window left at zero would quietly
// disarm the protection for every test after it.
func SetPurgeGraceForTest(d time.Duration) (restore func()) {
	old := purgeGracePeriod
	purgeGracePeriod = d
	return func() { purgeGracePeriod = old }
}

//go:build !darwin

package main

// On non-darwin builds launchd does not exist. selectServiceManager only asks
// for it when the family is darwin, which can only happen on darwin, so this
// stub is never selected at runtime; it exists so platform.go compiles on
// every target and fails closed if ever reached.

func newLaunchdServiceManager() ServiceManager {
	return noneServiceManager{reason: "launchd is only available on darwin"}
}

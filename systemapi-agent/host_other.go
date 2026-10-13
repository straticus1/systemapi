//go:build !linux

package main

import "fmt"

func hostLinux() bool { return false }

func errHostOS() error { return fmt.Errorf("requires linux") }

func hostLinuxOSRelease() (map[string]string, error) { return nil, errHostOS() }
func hostLinuxUname() (map[string]string, error)    { return nil, errHostOS() }
func hostLinuxHostname() (string, error)            { return "", errHostOS() }
func hostLinuxUptime() (string, error)              { return "", errHostOS() }
func hostLinuxUsers() ([]map[string]string, error)  { return nil, errHostOS() }
func hostLinuxGroups() ([]map[string]string, error) { return nil, errHostOS() }

func hostNetLinks() ([]map[string]string, error)     { return nil, errHostOS() }
func hostNetAddresses() ([]map[string]string, error) { return nil, errHostOS() }
func hostNetRoutes() ([]map[string]string, error)    { return nil, errHostOS() }
func hostNetSetAddress(iface, cidr string, allow []string) error {
	return errHostOS()
}
func hostNetSetDefaultRoute(iface, gateway string, allow []string) error {
	return errHostOS()
}
func hostNetLinkUp(iface string, allow []string) error   { return errHostOS() }
func hostNetLinkDown(iface string, allow []string) error { return errHostOS() }
func hostNetSetDNS(iface string, servers []string, allow []string) error {
	return errHostOS()
}

func hostDiskMounts() ([]map[string]string, error) { return nil, errHostOS() }
func hostDiskUsage(path string) (map[string]string, error) {
	return nil, errHostOS()
}
func hostDiskBlockDevices() ([]map[string]string, error) { return nil, errHostOS() }
func hostDiskMount(source, target, fstype string, readonly bool, allow []string) error {
	return errHostOS()
}
func hostDiskUmount(target string, allow []string) error { return errHostOS() }

func hostProcfsRead(rel string) (string, error) { return "", errHostOS() }
func hostSysctlGet(key string, allow []string) (string, error) {
	return "", errHostOS()
}
func hostSysctlSet(key, value string, allow []string) error { return errHostOS() }

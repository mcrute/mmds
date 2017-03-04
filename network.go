package main

import (
	"errors"
	"net"
	"os"
	"strings"

	jww "github.com/spf13/jwalterweatherman"
)

type interfaceContext struct {
	PrimaryIP       *net.IP
	MacAddr         *net.HardwareAddr
	PrimaryHostname *string
}

func interfaceIsUsable(i *net.Interface) bool {
	if i.Flags&net.FlagLoopback != 0 {
		return false
	}

	if i.Flags&net.FlagUp == 0 {
		return false
	}

	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return false
	}

	if strings.HasPrefix(i.Name, "docker") {
		return false
	}

	return true
}

func getPrimaryInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if len(ifaces) == 0 {
		return nil, errors.New("no interfaces found")
	}

	var iface net.Interface
	for _, iface = range ifaces {
		if !interfaceIsUsable(&iface) {
			continue
		} else {
			break
		}
	}

	if interfaceIsUsable(&iface) {
		return &iface, nil
	} else {
		return nil, errors.New("no usable interfaces found")
	}
}

func getInterfaceContext() (*interfaceContext, error) {
	iface, err := getPrimaryInterface()
	if err != nil {
		return nil, err
	}

	// Validated to have at least this in interfaceIsUsable
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	primaryAddr := addrs[0].String()
	primaryIP, _, err := net.ParseCIDR(primaryAddr)
	if err != nil {
		return nil, err
	}

	name, err := os.Hostname()
	if err != nil {
		jww.ERROR.Printf("Unable to resolve hostname, using localhost: %s", err.Error())
		name = "localhost"
	}

	return &interfaceContext{
		PrimaryIP:       &primaryIP,
		MacAddr:         &iface.HardwareAddr,
		PrimaryHostname: &name,
	}, nil
}

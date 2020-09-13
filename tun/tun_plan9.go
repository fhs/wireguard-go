/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for plan9
 */

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/rwcancel"
)

const (
	cloneDevicePath = "/dev/net/tun"
)

type NativeTun struct {
	tunFile, ctlFile        *os.File
	index                   int        // if index
	errors                  chan error // async error handling
	events                  chan Event // device related events
	nopi                    bool       // the device was passed IFF_NO_PI
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) MTU() (int, error) {
	sf, err := os.Open(fmt.Sprintf("/net/ipifc/%d/status", tun.index))
	if err != nil {
		return 0, err
	}
	defer sf.Close()

	b, err := ioutil.ReadAll(sf)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(b), "\n")
	f := strings.Fields(lines[0])
	log.Printf("read MTU %v\n", f[3])
	return strconv.Atoi(f[3])
}

func (tun *NativeTun) Name() (string, error) {
	return strconv.Itoa(tun.index), nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	return tun.tunFile.Write(buff[offset:])
}

func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	return tun.tunFile.Read(buff[offset:])
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	tun.tunFile.Close()
	return tun.ctlFile.Close()
}

func CreateTUN(name string, mtu int) (Device, error) {
	cf, err := os.OpenFile("/net/ipifc/clone", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(cf)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return nil, err
	}
	df, err := os.Open(fmt.Sprintf("/net/ipifc/%d/data", n))
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fprintf(cf, "bind pkt")
	if err != nil {
		return nil, err
	}
	log.Printf("setting mtu to %v\n", mtu)
	_, err = fmt.Fprintf(cf, "mtu %d", mtu)
	if err != nil {
		return nil, fmt.Errorf("setting mtu: %v", err)
	}
	return &NativeTun{
		tunFile: df,
		ctlFile: cf,
		index:   n,
	}, nil
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	panic("unimplemented")
}

func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	panic("unimplemented")
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux
// +build linux

package login

import (
	"collector/cache/user"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// Inode represents a file's inode on Linux.
type Inode uint64

const wtmpFile = "/var/log/wtmp"

// UtmpFile represents a UTMP file at a point in time.
type UtmpFile struct {
	Inode  Inode
	Size   int64
	Offset int64
}

type LoginRecord struct {
	UID      int
	Username string
	Time     time.Time
	IP       net.IP
	Hostname string
}

func (u *UtmpFile) GetRecord() (records []LoginRecord, err error) {
	var fileInfo fs.FileInfo
	fileInfo, err = os.Stat(wtmpFile)
	if err != nil {
		return
	}
	inode := Inode(fileInfo.Sys().(*syscall.Stat_t).Ino)
	// nothing new, return empty
	if fileInfo.Size() == u.Size && inode == u.Inode {
		return
	}

	// very first time or new inode
	if u.Inode == 0 || inode != u.Inode {
		u.Inode = inode
		u.Size = fileInfo.Size()
		u.Offset = 0
	}

	// check the size, if the size now is smaller than the record, start from new(may drop some records though)
	if fileInfo.Size() < u.Size {
		u.Size = fileInfo.Size()
		u.Offset = 0
	}

	var f *os.File
	f, err = os.Open(wtmpFile)
	if err != nil {
		return
	}
	_, err = f.Seek(u.Offset, 0)
	if err != nil {
		return
	}
	// Update the offset
	defer func() {
		if f != nil {
			offset, err := f.Seek(0, 1)
			if err == nil {
				u.Offset = offset
			}
		}
		f.Close()
	}()

	for {
		utmp, err := ReadNextUtmp(f)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if utmp == nil {
			break
		}
		switch utmp.UtType {
		case USER_PROCESS:
			uid, _ := strconv.ParseInt(user.Cache.GetUserFromName(utmp.UtUser).UID, 10, 64)
			records = append(records, LoginRecord{
				UID:      int(uid),
				IP:       newIP(utmp.UtAddrV6),
				Hostname: utmp.UtHost,
				Username: utmp.UtUser,
				Time:     utmp.UtTv,
			})
		}
	}
	return
}

func newIP(utAddrV6 [4]uint32) net.IP {
	var ip net.IP
	// See utmp(5) for the utmp struct fields.
	if utAddrV6[1] != 0 || utAddrV6[2] != 0 || utAddrV6[3] != 0 {
		// IPv6
		b := make([]byte, 16)
		byteOrder.PutUint32(b[:4], utAddrV6[0])
		byteOrder.PutUint32(b[4:8], utAddrV6[1])
		byteOrder.PutUint32(b[8:12], utAddrV6[2])
		byteOrder.PutUint32(b[12:], utAddrV6[3])
		ip = net.IP(b)
	} else {
		// IPv4
		b := make([]byte, 4)
		byteOrder.PutUint32(b, utAddrV6[0])
		ip = net.IP(b)
	}

	return ip
}

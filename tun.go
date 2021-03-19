package main

import (
	"bytes"
	"crypto/ed25519"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	iw "github.com/Arceliar/ironwood/net"
)

func setupTun(ifname, address string) tun.Device {
	dev, err := tun.CreateTUN(ifname, 1500)
	if err != nil {
		panic(err)
	}
	nladdr, err := netlink.ParseAddr(address)
	if err != nil {
		panic(err)
	}
	name, err := dev.Name()
	if err != nil {
		panic(err)
	}
	nlintf, err := netlink.LinkByName(name)
	if err != nil {
		panic(err)
	} else if err := netlink.AddrAdd(nlintf, nladdr); err != nil {
		panic(err)
	} else if err := netlink.LinkSetMTU(nlintf, 1500); err != nil {
		panic(err)
	} else if err := netlink.LinkSetUp(nlintf); err != nil {
		panic(err)
	}
	return dev
}

const tunOffsetBytes = 4

func tunReader(dev tun.Device, pc *iw.PacketConn) {
	localAddr := pc.LocalAddr()
	pubKey := *(*ed25519.PublicKey)(localAddr.(*iw.Addr))
	addrBytes := make([]byte, 16)
	addrBytes[0] = 0xfd
	copy(addrBytes[1:], pubKey)
	buf := make([]byte, 2048)
	for {
		n, err := dev.Read(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n <= tunOffsetBytes {
			panic("tunOffsetBytes")
		}
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		if len(bs) < 40 {
			panic("undersized packet")
		}
		// TODO read packet contents, pass to pc
		srcAddr := bs[8:24]
		dstAddr := bs[24:40]
		if !bytes.Equal(srcAddr, addrBytes) {
			//panic("wrong source address")
			continue
		}
		if dstAddr[0] != 0xfd {
			//panic("wrong dest subnet")
			continue
		}
		destKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		copy(destKey, dstAddr[1:])
		dest := (*iw.Addr)(&destKey)
		n, err = pc.WriteTo(bs, dest)
		if err != nil {
			panic(err)
		}
		if n != len(bs) {
			panic("failed to write full packet to packetconn")
		}
	}
}

func tunWriter(dev tun.Device, pc *iw.PacketConn) {
	localAddr := pc.LocalAddr()
	pubKey := *(*ed25519.PublicKey)(localAddr.(*iw.Addr))
	addrBytes := make([]byte, 16)
	addrBytes[0] = 0xfd
	copy(addrBytes[1:], pubKey)
	rawBuf := make([]byte, 2048)
	for {
		buf := rawBuf
		// We don't use full keys, so ReadUnderliverable instead of ReadFrom and check local
		n, local, remote, err := pc.ReadUndeliverable(buf[tunOffsetBytes:])
		if err != nil {
			panic(err)
		}
		if n < 40 {
			panic("undersized packet")
		}
		buf = buf[:tunOffsetBytes+n]
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		_, _ = local, remote // TODO check local and remote against srcAddr and destAddr
		srcAddr := bs[8:24]
		dstAddr := bs[24:40]
		if srcAddr[0] != 0xfd {
			//panic("wrong source subnet")
			continue
		}
		if dstAddr[0] != 0xfd {
			//panic("wrong dest subnet")
			continue
		}
		if !bytes.Equal(dstAddr, addrBytes) {
			//panic("wrong dest addr")
			continue
		}
		n, err = dev.Write(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n != len(buf) {
			panic("wrong number of bytes written")
		}
	}
}

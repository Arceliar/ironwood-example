package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	iwc "github.com/Arceliar/ironwood/encrypted"
	iwn "github.com/Arceliar/ironwood/network"
	iws "github.com/Arceliar/ironwood/signed"
	iwt "github.com/Arceliar/ironwood/types"

	"log"
	"net/http"
	_ "net/http/pprof"
)

var ifname = flag.String("ifname", "\000", "interface name to bind to")
var pprof = flag.String("pprof", "", "listen to pprof on this port")
var enc = flag.Bool("enc", false, "encrypt traffic (must be enabled on all nodes)")
var sign = flag.Bool("sign", false, "sign traffic (must be enabled on all nodes)")

func main() {
	flag.Parse()
	if pprof != nil && *pprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*pprof, nil))
		}()
	}
	_, key, _ := ed25519.GenerateKey(nil)
	var pc iwt.PacketConn
	if *enc && *sign {
		panic("TODO a useful error message (can't use both -unenc and -sign)")
	} else if *enc {
		pc, _ = iwc.NewPacketConn(key)
	} else if *sign {
		pc, _ = iws.NewPacketConn(key)
	} else {
		pc, _ = iwn.NewPacketConn(key)
	}
	defer pc.Close()
	// get address and pc.SetOutOfBandHandler
	localAddr := pc.LocalAddr()
	pubKey := ed25519.PublicKey(localAddr.(iwt.Addr))
	addrBytes := getAddr(pubKey)
	pc.SetOutOfBandHandler(func(from, to ed25519.PublicKey, data []byte) {
		if checkKey(addrBytes, to) {
			if len(data) < 1 {
				panic("DEBUG")
				return
			}
			switch data[0] {
			case oobKeyReq:
				res := []byte{oobKeyRes}    // TODO something useful, e.g. sign
				pc.SendOutOfBand(from, res) // TODO don't block
			case oobKeyRes:
				putKey(from)
				flushBuffer(pc, from)
			default:
				panic("DEBUG")
				return
			}
		}
	})
	// open tun/tap and assign address
	ip := net.IP(addrBytes[:])
	fmt.Println("Our IP address is", ip.String())
	if ifname != nil && *ifname != "none" {
		tun := setupTun(*ifname, ip.String()+"/8")
		// read/write between tun/tap and packetconn
		go tunReader(tun, pc)
		go tunWriter(tun, pc)
	}
	// open multicast and start adding peers
	mc := newMulticastConn()
	go mcSender(mc, pubKey)
	go mcListener(mc, pubKey, pc)
	// listen for TCP, pass connections to packetConn.HandleConn
	go listenTCP(pc)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	iw "github.com/Arceliar/ironwood"

	"log"
	"net/http"
	_ "net/http/pprof"
)

var ifname = flag.String("ifname", "\000", "interface name to bind to")
var pprof = flag.String("pprof", "", "listen to pprof on this port")

func init() {
	if pprof != nil && *pprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*pprof, nil))
		}()
	}
}

func main() {
	flag.Parse()
	_, key, _ := ed25519.GenerateKey(nil)
	pc, _ := iw.NewPacketConn(key)
	defer pc.Close()
	// get address and pc.SetRecvCheck
	localAddr := pc.LocalAddr()
	pubKey := *(*ed25519.PublicKey)(localAddr.(*iw.Addr))
	addrBytes := make([]byte, 16)
	addrBytes[0] = 0xfd
	copy(addrBytes[1:], pubKey)
	pc.SetRecvCheck(func(key ed25519.PublicKey) bool {
		return bytes.Equal(addrBytes[1:], key[:len(addrBytes)-1])
	})
	// open tun/tap and assign address
	ip := net.IP(addrBytes)
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

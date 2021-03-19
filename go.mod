module github.com/Arceliar/ironwood-example

go 1.16

require (
	github.com/Arceliar/ironwood v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4
	golang.org/x/sys v0.0.0-20210319071255-635bc2c9138d
	golang.zx2c4.com/wireguard v0.0.20201118
)

replace github.com/Arceliar/ironwood => ../ironwood

# pcapreplay

Version 0.0.1

pcapreplay is a simple library for replaying network traffic stored in a pcap
dump file. There are some existing bindings already but none of them worked to
scratch my particular itch. I wanted to keep this as simple as possible and
merely expose a high-level API to the libpcap underpinnings I needed.

This library could be easily extended into general-purpose high-level binding
to libpcap. As I need it, or as there is interest, i'll be fleshing this out.

## Installing
`go get github.com/aschepis/pcapreplay`

## Example
```go
package main

import (
	replay "github.com/aschepis/pcapreplay"
	"fmt"
	"encoding/binary"
)

type IPAddr uint32
type IPHeader struct {
	VersionIHL byte
	Tos byte
	TotalLength uint16
	Identification uint16
	FlagsFragOffset uint16
	TTL byte
	Protocol byte
	Checksum uint16
	Source IPAddr
	Dest IPAddr
	Options uint64
}

func NewIPHeader(packet []byte) *IPHeader {
	header := &IPHeader{}
	header.VersionIHL = packet[0]
	header.Tos = packet[1]

	header.TotalLength = binary.BigEndian.Uint16(packet[2:])
	header.Identification = binary.LittleEndian.Uint16(packet[4:])
	header.FlagsFragOffset = binary.LittleEndian.Uint16(packet[6:])
	header.TTL = packet[8]
	header.Protocol = packet[9]
	header.Checksum = binary.LittleEndian.Uint16(packet[10:])
	header.Source = IPAddr(binary.BigEndian.Uint32(packet[12:]))
	header.Dest = IPAddr(binary.BigEndian.Uint32(packet[16:]))
	header.Options = binary.LittleEndian.Uint64(packet[20:])
	return header
}

func (header *IPHeader) Version() byte {
	return header.VersionIHL >> 4
}

func formatIP(ip IPAddr) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24),
		byte(ip>>16), byte(ip>>8),
		byte(ip))
}

func (header *IPHeader) SourceIP() string {
	return formatIP(header.Source)
}

func (header *IPHeader) DestIP() string {
	return formatIP(header.Dest)
}

func main() {
	fmt.Println("pcap version: ", replay.PcapVersion())
	reader, err := replay.NewPacketReader("./traffic.pcapng")
	if err != nil {
		panic(err)
	}

	defer reader.Close()
	for {
		hdr, packet, err := reader.NextPacket()
		if err != nil {
			panic(err)
		} else if hdr == nil {
			break //eof
		}

		ipHeader := NewIPHeader(packet[14:])
		fmt.Printf("IP Protocol Version: %v\n", ipHeader.Version())
		fmt.Printf("Protocol: %v\n", ipHeader.Protocol)
		fmt.Printf("Total Length: %v\n", ipHeader.TotalLength)
		fmt.Printf("%v -> %v\n\n", ipHeader.SourceIP(), ipHeader.DestIP())
	}
}
```

## TODO

* Fill in PacketHeader with the data given by pcap_pkthdr struct
* Tests

## Contributing

By all means, please do! Pull requests and issues are welcome. No offical workflow yet.

## Versioning

pcapreplay uses semantic versioning. This is a bit pointless at the moment since the library
is yet to reach 1.0

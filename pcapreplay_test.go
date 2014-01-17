package pcapreplay
import (
	"fmt"
)

func ExamplePacketReader() {
	fmt.Println("pcap version: ", PcapVersion())
	reader, err := NewPacketReader("./traffic.pcapng")
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
		fmt.Println("got some data: ", packet)
	}
}
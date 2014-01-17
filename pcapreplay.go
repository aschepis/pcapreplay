// package pcapreplay provides functionality for streaming back saved network
// dumps in pcap or pcap-ng format from tcdpump, wireshark, etc.
package pcapreplay

/*
#cgo LDFLAGS: -lpcap
#include <pcap.h>

*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Get the version of libpcap running
func PcapVersion() string {
	return C.GoString(C.pcap_lib_version())
}

// PacketReader is an opaque type that exposes APIs for fetching packets
// from a pcap stream
type PacketReader struct {
	pcap          *C.struct_pcap_t
	currentHeader *C.struct_pcap_pkthdr
	currentPacket *[]byte
}

// TODO: Not useful yet.
type PacketHeader struct {
}

// Create a new PacketReader using a saved pcap file
func NewPacketReader(path string) (*PacketReader, error) {
	pcap := C.pcap_open_offline(C.CString(path), nil)
	if pcap == nil {
		return nil, fmt.Errorf("failed to open pcap file: %v", path)
	}
	return &PacketReader{pcap: pcap}, nil
}

// Close the PacketReader and release any resources being held.
func (reader *PacketReader) Close() {
	C.pcap_close(reader.pcap)
	reader.pcap = nil
}

// Get the next packet from the stream
func (reader *PacketReader) NextPacket() (*PacketHeader, []byte, error) {
	result := C.pcap_next_ex(reader.pcap,
		(**C.struct_pcap_pkthdr)(unsafe.Pointer(&reader.currentHeader)),
		(**C.u_char)(unsafe.Pointer(&reader.currentPacket)))
	if result == -2 {
		return nil, nil, nil
	} else if result != 1 {
		return nil, nil, fmt.Errorf(C.GoString(C.pcap_geterr(reader.pcap)))
	}

	packet := C.GoBytes(unsafe.Pointer(reader.currentPacket),
		C.int(reader.currentHeader.len))
	return &PacketHeader{}, packet, nil
}

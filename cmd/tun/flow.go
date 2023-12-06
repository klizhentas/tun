package main

import (
	"github.com/google/gopacket"

	"github.com/songgao/water"
)

type TunPacketReader struct {
	iface *water.Interface
}

func (tr *TunPacketReader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	packet := make([]byte, 2000)
	n, err := tr.iface.Read(packet)
	if err != nil {
		return nil, ci, err
	}
	return packet[:n], ci, nil
}

func NewTunPacketReader(iface *water.Interface) gopacket.PacketDataSource {
	return &TunPacketReader{iface: iface}
}

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
)

func main() {
	fd, err := openDevSystem("")
	if err != nil {
		slog.Error("Failed to open system device: %v", err)
		os.Exit(-1)
	}
	defer fd.Close()
	slog.Info("Opened device: %v", fd.Name())

	rand.Seed(time.Now().UnixNano())

	// Create the stack with ipv4 and tcp protocols, then add a tun-based
	// NIC and ipv4 address.
	ustack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	mtu := 1500

	slog.Info("Metrics: MTU: %s", mtu)

	dev, err := tun.CreateTUN("utun5", mtu)
	if err != nil {
		slog.Error("Failed to create tun device: %v", err)
		return
	}
	devName, err := dev.Name()
	if err != nil {
		slog.Error("Failed to get device name: %s", err)
	}
	slog.Info("created tun device: %s", devName)

	const nicID = 1

	linkEP := channel.New(512, uint32(mtu), "")
	if err := ustack.CreateNIC(nicID, linkEP); err != nil {
		slog.Error("can't create nic: %v", err)
		return
	}
	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since WireGuard will only send us packets that are meant for us.
	ustack.SetPromiscuousMode(nicID, true)

	ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		slog.Error("Failed to create IPV4 subnet", slog.String("err", err.Error()))
		return
	}
	ipv6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		slog.Error("Failed to create IPV6 subnet", slog.String("err", err.Error()))
	}
	ustack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})

	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpForwarder := tcp.NewForwarder(ustack, 0, 1024, func(req *tcp.ForwarderRequest) {
		reqID := req.ID()
		slog.Info("got forward request", "src", fromNetstackIP(reqID.RemoteAddress), "dst", fromNetstackIP(reqID.LocalAddress))
		dstIP := reqID.LocalAddress
		// Add address as route dynamically (has to be concurrent in the future)
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: dstIP.WithPrefix(),
			// TODO: Add IPV6
			Protocol: ipv4.ProtocolNumber,
		}

		// TODO has to be concurrent properly
		ustack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})

		var wq waiter.Queue
		endpoint, err := req.CreateEndpoint(&wq)
		if err != nil {
			slog.Error("Failed to create endpoint: %v", err)
			req.Complete(false)
			return
		}
		slog.Info("req ID before", "req", reqID)
		req.Complete(true)
		endpoint.SocketOptions().SetKeepAlive(true)
		// lots of useful comments here:
		// https://github.com/tailscale/tailscale/blob/main/wgengine/netstack/netstack.go#L890
		client := gonet.NewTCPConn(&wq, endpoint)
		defer client.Close()
		slog.Info("Req: ", "req", reqID)
		srcIP := fromNetstackIP(reqID.RemoteAddress)
		// For now let's forward everything to localhost but on the same port
		dstAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(reqID.LocalPort))
		slog.Info("Forward", slog.String("src", srcIP.String()), slog.String("dst", dstAddr.String()))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)
		done := make(chan bool)
		// netstack doesn't close the notification channel automatically if there was no
		// hup signal, so we close done after we're done to not leak the goroutine below.
		defer close(done)
		go func() {
			select {
			case <-notifyCh:
				slog.Info("netstack forwardTCP notified, canceling context for %s", dstAddr)
			case <-done:
			}
			cancel()
		}()

		// Attempt to dial the outbound connection before we accept the inbound one.
		var dialer net.Dialer
		server, dialerr := dialer.DialContext(ctx, "tcp", dstAddr.String())
		if dialerr != nil {
			slog.Info("could not connect to local server", "dst", dstAddr.String(), "err", dialerr)
			return
		}
		defer server.Close()

		connClosed := make(chan error, 2)
		go func() {
			_, err := io.Copy(server, client)
			connClosed <- err
		}()
		go func() {
			_, err := io.Copy(client, server)
			connClosed <- err
		}()
		dialerr = <-connClosed
		if err != nil {
			slog.Info("proxy connection closed with error", "err", err)
		}
		slog.Info("forwarder connection to %s closed", dstAddr)
		return

	})
	ctx := context.Background()

	ustack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	go forwardTunnelToEndpoint(dev, linkEP)
	go forwardEndpointToTunnel(ctx, linkEP, dev)
	go func() {
		for {
			<-time.NewTicker(10 * time.Second).C
			stats := ustack.Stats()
			slog.Info("TCP stats:",
				"ip-malformed-packets-received", stats.IP.MalformedPacketsReceived,
				"total-packets-received-bytes", stats.NICs.Rx.Bytes,
				"total-packets-received-count", stats.NICs.Rx.Packets,
			)
		}
	}()

	time.Sleep(10000 * time.Second)
}

func forwardEndpointToTunnel(ctx context.Context, endpoint *channel.Endpoint, tun tun.Device) {
	for {
		packet := endpoint.ReadContext(ctx)
		if packet.IsNil() {
			slog.Warn("got nil packet")
			continue
		}
		buf := packet.ToBuffer()
		bytes := (&buf).Flatten()
		const writeOffset = device.MessageTransportHeaderSize
		moreBytes := make([]byte, writeOffset, len(bytes)+writeOffset)
		moreBytes = append(moreBytes[:writeOffset], bytes...)
		slog.Info("Forwarding packet to endpoint", "packet-size", len(moreBytes))

		if _, err := tun.Write([][]byte{moreBytes}, writeOffset); err != nil {
			slog.Error("failed to inject inbound", slog.String("err", err.Error()))
			return
		}
		slog.Info("forwarded one packet to tunnel")
	}
}

func forwardTunnelToEndpoint(tun tun.Device, dstEndpoint *channel.Endpoint) error {
	buffers := make([][]byte, tun.BatchSize())
	for i := range buffers {
		buffers[i] = make([]byte, device.MaxMessageSize)
	}
	const readOffset = device.MessageTransportHeaderSize
	sizes := make([]int, len(buffers))
	for {
		for i := range buffers {
			buffers[i] = buffers[i][:cap(buffers[i])]
		}
		n, err := tun.Read(buffers, sizes, readOffset)
		slog.Info("read packets", "count", n)
		if err != nil {
			slog.Error("Failed to read from tun", "err", err)
			return err
		}
		for i := range sizes[:n] {
			buffers[i] = buffers[i][readOffset : readOffset+sizes[i]]
			slog.Info("Buffer size", "len", len(buffers[i]), "size", sizes[i], "readOffset", readOffset)
			// ready to send data to channel
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buffers[i])),
			})
			/*if !parse.IPv4(packetBuf) {
				slog.Error("Failed to parse packets")
			}*/
			slog.Info("endpoint is not attached?", slog.Bool("attached", dstEndpoint.IsAttached()))
			dstEndpoint.InjectInbound(header.IPv4ProtocolNumber, packetBuf)
			slog.Info("sent one packet to dstEndpoint")
			packetBuf.DecRef()
		}
	}
}

func fromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		s := s.As4()
		return netip.AddrFrom4([4]byte{s[0], s[1], s[2], s[3]})
	case 16:
		s := s.As16()
		return netip.AddrFrom16(s).Unmap()
	}
	return netip.Addr{}
}

// Lots of code and samples taken from here:
// https://github.com/tailscale/tailscale/blob/main/wgengine/netstack/netstack.go#L202
// Copyright, etc, etc, etc.
package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

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

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	procCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create the stack with ipv4 and tcp protocols, then add a tun-based
	// NIC and ipv4 address.
	ustack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	// TODO: There is got to be a syscall that tells MTU?
	mtu := 1500

	slog.Info("Setting up TUN device with parameters", slog.Int("mtu", mtu))

	dev, err := tun.CreateTUN("utun5", mtu)
	if err != nil {
		slog.Error("Failed to create tun device", slog.String("err", err.Error()))
		return
	}
	devName, err := dev.Name()
	if err != nil {
		slog.Error("Failed to get device name.", slog.String("err", err.Error()))
	}
	slog.Info("Created tun device.", "name", devName)

	const nicID = 1

	linkEP := channel.New(512, uint32(mtu), "")
	if err := ustack.CreateNIC(nicID, linkEP); err != nil {
		slog.Error("can't create nic: %v", err)
		return
	}
	// Comment taken from here:
	//
	// https://github.com/tailscale/tailscale/blob/main/wgengine/netstack/netstack.go#L202
	//
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
		slog.Info("Fot TCP forward request.", slog.String("src", fromNetstackIP(reqID.RemoteAddress).String()), slog.String("dst", fromNetstackIP(reqID.LocalAddress).String()))
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
			slog.Error("Failed to create endpoint.", slog.String("err", err.String()))
			req.Complete(false)
			return
		}
		req.Complete(true)
		endpoint.SocketOptions().SetKeepAlive(true)
		// lots of useful comments here:
		// https://github.com/tailscale/tailscale/blob/main/wgengine/netstack/netstack.go#L890
		client := gonet.NewTCPConn(&wq, endpoint)
		defer client.Close()
		srcIP := fromNetstackIP(reqID.RemoteAddress)
		// For now let's forward everything to localhost but on the same port
		dstAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(reqID.LocalPort))
		slog.Info("Forwarding.", slog.String("src", srcIP.String()), slog.String("dst", dstAddr.String()))

		ctx, cancel := context.WithCancel(procCtx)
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
				slog.Info("Netstack forwardTCP notified, canceling context for.", slog.String("dst", dstAddr.String()))
			case <-done:
			}
			cancel()
		}()

		// Attempt to dial the outbound connection before we accept the inbound one.
		var dialer net.Dialer
		server, dialerr := dialer.DialContext(ctx, "tcp", dstAddr.String())
		if dialerr != nil {
			slog.Info("Could not connect to local server.", slog.String("dst", dstAddr.String()), slog.String("err", dialerr.Error()))
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
			slog.Error("Proxy connection closed with error.", slog.String("err", err.String()))
		}
		slog.Info("Forwarder connection closed.", slog.String("dst", dstAddr.String()))
		return
	})

	ustack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	go forwardTunnelToEndpoint(procCtx, dev, linkEP)
	go forwardEndpointToTunnel(procCtx, linkEP, dev)

	statsC := make(chan os.Signal, 1)
	signal.Notify(statsC, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-procCtx.Done():
				return
			case <-statsC:
				stats := ustack.Stats()
				slog.Info("Got USR1, printing TCP stats",
					"ip-malformed-packets-received", stats.IP.MalformedPacketsReceived,
					"total-packets-received-bytes", stats.NICs.Rx.Bytes,
					"total-packets-received-count", stats.NICs.Rx.Packets,
				)
			}

		}
	}()

	<-procCtx.Done()
	slog.Info("Got exit singal. Shutting down.")
}

func forwardEndpointToTunnel(ctx context.Context, endpoint *channel.Endpoint, tun tun.Device) {
	for {
		packet := endpoint.ReadContext(ctx)
		if packet.IsNil() {
			continue
		}
		buf := packet.ToBuffer()
		bytes := (&buf).Flatten()
		const writeOffset = device.MessageTransportHeaderSize
		moreBytes := make([]byte, writeOffset, len(bytes)+writeOffset)
		moreBytes = append(moreBytes[:writeOffset], bytes...)

		if _, err := tun.Write([][]byte{moreBytes}, writeOffset); err != nil {
			slog.Error("failed to inject inbound", slog.String("err", err.Error()))
			return
		}
	}
}

func forwardTunnelToEndpoint(ctx context.Context, tun tun.Device, dstEndpoint *channel.Endpoint) error {
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
		if err != nil {
			slog.Error("Failed to read from tun", "err", err)
			return err
		}
		for i := range sizes[:n] {
			buffers[i] = buffers[i][readOffset : readOffset+sizes[i]]
			// ready to send data to channel
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buffers[i])),
			})
			dstEndpoint.InjectInbound(header.IPv4ProtocolNumber, packetBuf)
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

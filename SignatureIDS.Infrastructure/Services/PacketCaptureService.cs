using PacketDotNet;
using SharpPcap;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Infrastructure.Services
{
    public class PacketCaptureService : IPacketCaptureService, IDisposable
    {
        private ICaptureDevice? _device;

        public void StartCapture(string interfaceName, Action<PacketHeaders> onPacker)
        {
            _device = CaptureDeviceList.Instance.FirstOrDefault(d => d.Name == interfaceName) ?? throw new InvalidOperationException($"Interface `{interfaceName}` not found");

            _device.OnPacketArrival += (_, e) =>
            {
                var raw = e.GetPacket();
                var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
                var headers = Parse(packet, raw.Timeval.Date);
                if(headers is not null)
                {
                    onPacker(headers);
                }
            };

            _device.Open(DeviceModes.Promiscuous);
            _device.StartCapture();
        }

        private static PacketHeaders? Parse(Packet raw, DateTime timestamp)
        {
            var headers = new PacketHeaders
            {
                Timestamp = timestamp
            };

            //ARP
            var arp = raw.Extract<ArpPacket>();
            if(arp is not null)
            {
                headers.Protocol = "ARP";
                headers.SrcIp = arp.SenderProtocolAddress.ToString();
                headers.DstIp = arp.TargetProtocolAddress.ToString();
                headers.IsArpReply = arp.Operation == ArpOperation.Response;
                return headers;
            }

            var ip = raw.Extract<IPPacket>();
            if (ip is null) return null;

            headers.SrcIp = ip.SourceAddress.ToString();
            headers.DstIp = ip.DestinationAddress.ToString();
            headers.PacketLength = ip.TotalLength;

            //TCP
            var tcp = raw.Extract<TcpPacket>();
            if(tcp is not null)
            {
                headers.Protocol = "TCP";
                headers.SrcPort = tcp.SourcePort;
                headers.DstPort = tcp.DestinationPort;
                headers.FinFlag = tcp.Finished;
                headers.SynFlag = tcp.Synchronize;
                headers.RstFlag = tcp.Reset;
                headers.PshFlag = tcp.Push;
                headers.AckFlag = tcp.Acknowledgment;
                headers.WindowSize = tcp.WindowSize;
                headers.Payload = tcp.PayloadData ?? [];
                headers.HeaderLength = tcp.DataOffset * 4;
                return headers;
            }

            //UDP
            var udp = raw.Extract<UdpPacket>();
            if(udp is not null)
            {
                headers.Protocol = "UDP";
                headers.SrcPort = udp.SourcePort;
                headers.DstPort = udp.DestinationPort;
                headers.Payload = udp.PayloadData ?? [];
                headers.HeaderLength = 8; //UDP header is always 8 bytes
                return headers;
            }

            //ICMP
            var icmp4 = raw.Extract<IcmpV4Packet>();
            if(icmp4 is not null)
            {
                headers.Protocol = "ICMP";
                headers.Payload = icmp4.PayloadData ?? [];
                headers.HeaderLength = 8; //ICMP header is typically 8 bytes
                return headers;
            }

            var icmp6 = raw.Extract<IcmpV6Packet>();
            if(icmp6 is not null)
            {
                headers.Protocol = "ICMPv6";
                headers.Payload = icmp6.PayloadData ?? [];
                headers.HeaderLength = 8; //ICMPv6 header is typically 8 bytes
                return headers;
            }

            return null;
        }

        public void Dispose()
        {
            if (_device is null) return;
            if(_device.Started) _device.StopCapture();
            _device.Close();
            _device.Dispose();
            _device = null;
        }
    }
}

using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;

namespace SignatureIDS.Infrastructure.Services;

public class FlowFeatureExtractor : IFlowFeatureExtractor
{
    public FlowFeatures Extract(IReadOnlyList<PacketHeaders> packets)
    {
        if (packets.Count == 0)
            return new FlowFeatures();

        // Sort chronologically so the true flow initiator is always first
        var sorted = packets.OrderBy(p => p.Timestamp).ToList();
        var first = sorted[0];
        string srcIp = first.SrcIp;

        // Split into forward (same src as chronological first) and backward
        var fwd = sorted.Where(p => p.SrcIp == srcIp).ToList();
        var bwd = sorted.Where(p => p.SrcIp != srcIp).ToList();

        // Packet lengths
        var allLengths = sorted.Select(p => (double)p.PacketLength).ToList();
        var fwdLengths = fwd.Select(p => (double)p.PacketLength).ToList();
        var bwdLengths = bwd.Select(p => (double)p.PacketLength).ToList();

        double totSum = allLengths.Sum();
        double min = allLengths.Min();
        double max = allLengths.Max();
        double avg = allLengths.Average();
        double variance = allLengths.Average(l => Math.Pow(l - avg, 2));
        double std = Math.Sqrt(variance);

        // Flow duration in seconds — sorted is already ordered so just use first/last
        var timestamps = sorted.Select(p => p.Timestamp).ToList();
        double flowDuration = (timestamps.Last() - timestamps.First()).TotalSeconds;

        // IAT — mean inter-arrival time in seconds
        double iat = 0;
        if (timestamps.Count > 1)
        {
            var iats = new List<double>();
            for (int i = 1; i < timestamps.Count; i++)
                iats.Add((timestamps[i] - timestamps[i - 1]).TotalSeconds);
            iat = iats.Average();
        }

        // ARP epsilon packets also use sorted order
        var arpPackets = sorted.Where(p => p.Protocol.Equals("ARP", StringComparison.OrdinalIgnoreCase)).ToList();

        // Flow rates (packets/s and bytes/s), guard against zero duration
        double flowBytess = flowDuration > 0 ? totSum / flowDuration : 0;
        double fwdPacketss = flowDuration > 0 ? fwd.Count / flowDuration : 0;
        double bwdPacketss = flowDuration > 0 ? bwd.Count / flowDuration : 0;
        double rate = flowDuration > 0 ? sorted.Count / flowDuration : 0;

        // Aggregate flag counts across all packets
        int finCount = sorted.Count(p => p.FinFlag);
        int synCount = sorted.Count(p => p.SynFlag);
        int rstCount = sorted.Count(p => p.RstFlag);
        int pshCount = sorted.Count(p => p.PshFlag);
        int ackCount = sorted.Count(p => p.AckFlag);
        int bwdPsh = bwd.Count(p => p.PshFlag);

        // Protocol detection — inspect first (or any) packet's Protocol field
        string proto = first.Protocol.ToUpperInvariant();
        bool isTcp = proto == "TCP";
        bool isUdp = proto == "UDP";
        bool isIcmp = proto == "ICMP";
        bool isArp = proto == "ARP";
        bool isIgmp = proto == "IGMP";

        // IANA protocol numbers
        int protocolType = proto switch
        {
            "TCP" => 6,
            "UDP" => 17,
            "ICMP" => 1,
            "IGMP" => 2,
            _ => 0
        };

        // Port-based protocol indicators (use first packet's DstPort)
        int dstPort = first.DstPort ?? 0;
        bool isHttp = isTcp && dstPort == 80;
        bool isHttps = isTcp && dstPort == 443;
        bool isDns = (isTcp || isUdp) && dstPort == 53;
        bool isTelnet = isTcp && dstPort == 23;
        bool isSmtp = isTcp && (dstPort == 25 || dstPort == 587);
        bool isSsh = isTcp && dstPort == 22;
        bool isIrc = isTcp && (dstPort == 6667 || dstPort == 6668);
        bool isDhcp = isUdp && (dstPort == 67 || dstPort == 68);

        // Header lengths
        double fwdHeaderLen = fwd.Count > 0 ? fwd.Average(p => (double)p.HeaderLength) : 0;
        double bwdHeaderLen = bwd.Count > 0 ? bwd.Average(p => (double)p.HeaderLength) : 0;

        // Window sizes (init window bytes)
        double initWinFwd = fwd.Count > 0 ? fwd[0].WindowSize ?? 0 : 0;
        double initWinBwd = bwd.Count > 0 ? bwd[0].WindowSize ?? 0 : 0;

        // ActDataPktFwd — forward packets with non-zero payload
        int actDataPktFwd = fwd.Count(p => p.Payload.Length > 0);

        // ConnectionAttempts — SYN packets in forward direction
        int connectionAttempts = fwd.Count(p => p.SynFlag);

        // ARP epsilon features
        double epsilon1 = 0;
        double epsilon2 = 0;
        if (arpPackets.Count > 0)
        {
            int arpReplies = arpPackets.Count(p => p.IsArpReply);
            int arpRequests = arpPackets.Count - arpReplies;
            int uniqueSenderIps = arpPackets.Select(p => p.SrcIp).Distinct().Count();
            epsilon1 = arpReplies / (double)(arpRequests + 1);
            epsilon2 = uniqueSenderIps / (double)arpPackets.Count;
        }

        return new FlowFeatures
        {
            // Top-level
            HeaderLength = first.HeaderLength,
            ProtocolType = protocolType,
            TimeToLive = 0,         // not captured in PacketHeaders
            Rate = rate,

            // Flag counts
            FinFlagNumber = finCount,
            SynFlagNumber = synCount,
            RstFlagNumber = rstCount,
            PshFlagNumber = pshCount,
            AckFlagNumber = ackCount,
            EceFlagNumber = 0,      // not captured
            CwrFlagNumber = 0,      // not captured

            // Protocol indicators
            Http = isHttp ? 1 : 0,
            Https = isHttps ? 1 : 0,
            Dns = isDns ? 1 : 0,
            Telnet = isTelnet ? 1 : 0,
            Smtp = isSmtp ? 1 : 0,
            Ssh = isSsh ? 1 : 0,
            Irc = isIrc ? 1 : 0,
            Tcp = isTcp ? 1 : 0,
            Udp = isUdp ? 1 : 0,
            Dhcp = isDhcp ? 1 : 0,
            Arp = isArp ? 1 : 0,
            Icmp = isIcmp ? 1 : 0,
            Igmp = isIgmp ? 1 : 0,
            Ipv = 0,                // not distinguished (assume IPv4)
            Llc = 0,                // not captured

            // Statistical aggregates
            TotSum = totSum,
            Min = min,
            Max = max,
            Avg = avg,
            Std = std,
            Iat = iat,
            Number = sorted.Count,
            Variance = variance,

            // Flow identifiers
            DestinationPort = dstPort,
            ConnectionAttempts = connectionAttempts,

            // Packet length features
            FwdPacketLengthMax = fwdLengths.Count > 0 ? fwdLengths.Max() : 0,
            FwdPacketLengthMin = fwdLengths.Count > 0 ? fwdLengths.Min() : 0,
            BwdPacketLengthMax = bwdLengths.Count > 0 ? bwdLengths.Max() : 0,
            BwdPacketLengthMin = bwdLengths.Count > 0 ? bwdLengths.Min() : 0,
            MinPacketLength = min,
            MaxPacketLength = max,
            FwdHeaderLength = fwdHeaderLen,
            BwdHeaderLength = bwdHeaderLen,
            InitWinBytesForward = initWinFwd,
            InitWinBytesBackward = initWinBwd,

            // Flow-level flags
            BwdPshFlags = bwdPsh,

            // Flow statistics
            FlowDuration = flowDuration,
            TotalLengthOfFwdPackets = fwdLengths.Sum(),
            TotalLengthOfBwdPackets = bwdLengths.Sum(),
            FlowBytess = flowBytess,
            FwdPacketss = fwdPacketss,
            BwdPacketss = bwdPacketss,
            AveragePacketSize = avg,
            FwdPacketLengthMean = fwdLengths.Count > 0 ? fwdLengths.Average() : 0,
            BwdPacketLengthMean = bwdLengths.Count > 0 ? bwdLengths.Average() : 0,
            PacketLengthMean = avg,
            ActDataPktFwd = actDataPktFwd,

            // ARP epsilon
            Epsilon1ArpReplyRatio = epsilon1,
            Epsilon2SenderIpDensity = epsilon2,
        };
    }
}

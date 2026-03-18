namespace SignatureIDS.Core.DTO.Detection;

public class FlowFeatures
{
    // Top-level packet features
    public int HeaderLength { get; set; }
    public int ProtocolType { get; set; }
    public int TimeToLive { get; set; }
    public double Rate { get; set; }

    // Flag numbers (raw per-packet)
    public int FinFlagNumber { get; set; }
    public int SynFlagNumber { get; set; }
    public int RstFlagNumber { get; set; }
    public int PshFlagNumber { get; set; }
    public int AckFlagNumber { get; set; }
    public int EceFlagNumber { get; set; }
    public int CwrFlagNumber { get; set; }

    // Protocol indicators (0 or 1)
    public int Http { get; set; }
    public int Https { get; set; }
    public int Dns { get; set; }
    public int Telnet { get; set; }
    public int Smtp { get; set; }
    public int Ssh { get; set; }
    public int Irc { get; set; }
    public int Tcp { get; set; }
    public int Udp { get; set; }
    public int Dhcp { get; set; }
    public int Arp { get; set; }
    public int Icmp { get; set; }
    public int Igmp { get; set; }
    public int Ipv { get; set; }
    public int Llc { get; set; }

    // Statistical aggregates
    public double TotSum { get; set; }
    public double Min { get; set; }
    public double Max { get; set; }
    public double Avg { get; set; }
    public double Std { get; set; }
    public double Iat { get; set; }
    public int Number { get; set; }
    public double Variance { get; set; }

    // Flow identifiers
    public int DestinationPort { get; set; }
    public int ConnectionAttempts { get; set; }

    // Packet length features
    public double FwdPacketLengthMax { get; set; }
    public double FwdPacketLengthMin { get; set; }
    public double BwdPacketLengthMax { get; set; }
    public double BwdPacketLengthMin { get; set; }
    public double MinPacketLength { get; set; }
    public double MaxPacketLength { get; set; }
    public double FwdHeaderLength { get; set; }
    public double BwdHeaderLength { get; set; }
    public double InitWinBytesForward { get; set; }
    public double InitWinBytesBackward { get; set; }

    // Flow-level flags
    public int BwdPshFlags { get; set; }

    // Flow statistics
    public double FlowDuration { get; set; }
    public double TotalLengthOfFwdPackets { get; set; }
    public double TotalLengthOfBwdPackets { get; set; }
    public double FlowBytess { get; set; }
    public double FwdPacketss { get; set; }
    public double BwdPacketss { get; set; }
    public double AveragePacketSize { get; set; }
    public double FwdPacketLengthMean { get; set; }
    public double BwdPacketLengthMean { get; set; }
    public double PacketLengthMean { get; set; }
    public int ActDataPktFwd { get; set; }

    // ARP epsilon features (real-time windowed computation)
    public double Epsilon1ArpReplyRatio { get; set; }
    public double Epsilon2SenderIpDensity { get; set; }
}

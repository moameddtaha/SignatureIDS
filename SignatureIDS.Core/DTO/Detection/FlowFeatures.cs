namespace SignatureIDS.Core.DTO.Detection;

public class FlowFeatures
{
    public int DestinationPort { get; set; }
    public int ConnectionAttempts { get; set; }
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
    public double MinSegSizeForward { get; set; }
    public int FinFlagCount { get; set; }
    public int SynFlagCount { get; set; }
    public int RstFlagCount { get; set; }
    public int PshFlagCount { get; set; }
    public int AckFlagCount { get; set; }
    public int FwdPshFlags { get; set; }
    public int BwdPshFlags { get; set; }
    public double FlowDuration { get; set; }
    public int TotalFwdPackets { get; set; }
    public int TotalBackwardPackets { get; set; }
    public double TotalLengthOfFwdPackets { get; set; }
    public double TotalLengthOfBwdPackets { get; set; }
    public double FlowBytes { get; set; }
    public double FlowPackets { get; set; }
    public double FwdPackets { get; set; }
    public double BwdPackets { get; set; }
    public double DownUpRatio { get; set; }
    public double AveragePacketSize { get; set; }
    public double FwdPacketLengthMean { get; set; }
    public double BwdPacketLengthMean { get; set; }
    public double PacketLengthMean { get; set; }
    public int ActDataPktFwd { get; set; }
}

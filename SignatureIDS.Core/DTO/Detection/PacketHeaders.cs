namespace SignatureIDS.Core.DTO.Detection;

public class PacketHeaders
{
    public string Protocol { get; set; } = string.Empty;
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int? SrcPort { get; set; }
    public int? DstPort { get; set; }
    public byte[] Payload { get; set; } = [];
    public int PacketLength { get; set; }
    public int HeaderLength { get; set; }
    public DateTime Timestamp { get; set; }
    public bool FinFlag { get; set; }
    public bool SynFlag { get; set; }
    public bool RstFlag { get; set; }
    public bool PshFlag { get; set; }
    public bool AckFlag { get; set; }
    public int? WindowSize { get; set; }
    public bool IsArpReply { get; set; }
}

namespace SignatureIDS.Core.DTO.Detection;

public class AlertDto
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public int? Sid { get; set; }
    public string Msg { get; set; } = string.Empty;
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int? SrcPort { get; set; }
    public int? DstPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string DetectionSource { get; set; } = string.Empty;
}

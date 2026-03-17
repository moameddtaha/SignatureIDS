namespace SignatureIDS.Core.DTO.Rules;

public class RuleDto
{
    public int Sid { get; set; }
    public string Msg { get; set; } = string.Empty;
    public string Proto { get; set; } = string.Empty;
    public string SrcPort { get; set; } = "any";
    public string DstPort { get; set; } = "any";
    public string? Content { get; set; }
    public bool? Nocase { get; set; }
    public string Category { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
}

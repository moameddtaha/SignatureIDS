using SignatureIDS.Core.Domain.Entity;

namespace SignatureIDS.Core.DTO.Detection;

public class DetectionResult
{
    public bool IsMatch { get; set; }
    public Rule? MatchedRule { get; set; }
}

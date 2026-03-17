namespace SignatureIDS.Core.DTO.Detection;

public class MlResult
{
    public bool IsAttack { get; set; }
    public string? AttackType { get; set; }
    public AlertDto? Alert { get; set; }
}

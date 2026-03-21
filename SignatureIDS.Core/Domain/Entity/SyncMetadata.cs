namespace SignatureIDS.Core.Domain.Entity;

public class SyncMetadata
{
    public string Id { get; set; } = "rules_sync";
    public DateTime LastSyncedAt { get; set; }
}

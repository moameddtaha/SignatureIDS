using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

/// <summary>
/// Matches packet headers against the loaded signature rules.
/// </summary>
public interface ISignatureDetectionService
{
    /// <summary>
    /// Evaluates the packet headers against all active rules.
    /// Returns a <see cref="DetectionResult"/> if a rule matches, or <c>null</c> if no match is found.
    /// </summary>
    /// <param name="headers">The parsed headers of the captured packet.</param>
    Task<DetectionResult?> DetectAsync(PacketHeaders headers);
}

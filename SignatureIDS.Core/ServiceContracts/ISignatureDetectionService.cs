using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

public interface ISignatureDetectionService
{
    Task<DetectionResult?> DetectAsync(PacketHeaders headers);
}

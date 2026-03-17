using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

public interface IFlowFeatureExtractor
{
    FlowFeatures Extract(PacketHeaders headers);
}

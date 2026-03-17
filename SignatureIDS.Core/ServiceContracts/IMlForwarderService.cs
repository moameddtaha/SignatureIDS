using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

public interface IMlForwarderService
{
    Task<MlResult> ForwardAsync(string csv);
}

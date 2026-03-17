using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

public interface IAlertDispatcherService
{
    Task SendAsync(AlertDto alert);
}

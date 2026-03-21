using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

/// <summary>
/// Dispatches security alerts to the Dashboard API.
/// </summary>
public interface IAlertDispatcherService
{
    /// <summary>
    /// Sends the given alert to the Dashboard API.
    /// </summary>
    /// <param name="alert">The alert to dispatch.</param>
    Task SendAsync(AlertDto alert);
}

using Microsoft.Extensions.Logging;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;
using System.Net.Http.Json;
using System.Net.Http;

namespace SignatureIDS.Infrastructure.Services
{
    public class AlertDispatcherService : IAlertDispatcherService
    {
        private const string AlertsEndpoint = "api/alerts";

        private readonly HttpClient _http;
        private readonly ILogger<AlertDispatcherService> _logger;

        public AlertDispatcherService(IHttpClientFactory factory, ILogger<AlertDispatcherService> logger)
        {
            _http = factory.CreateClient("DashbaordApi");
            _logger = logger;
        }

        public async Task SendAsync(AlertDto alert)
        {
            try
            {
                var response = await _http.PostAsJsonAsync(AlertsEndpoint, alert);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Alert dispatched successfully: {Alert}", alert);
                }
                else
                {
                    _logger.LogError("Failed to dispatch alert. Status Code: {StatusCode}, Response: {Response}", response.StatusCode, await response.Content.ReadAsStringAsync());
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while dispatching alert: {Alert} to Dashboard API", alert);
            }
        }
    }
}

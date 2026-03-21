using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;
using System.Net.Http.Json;
using System.Net.Http;

namespace SignatureIDS.Infrastructure.Services
{
    public class AlertDispatcherService : IAlertDispatcherService
    {
        private readonly HttpClient _http;
        private readonly ILogger<AlertDispatcherService> _logger;
        private readonly string _endpoint;

        public AlertDispatcherService(HttpClient http, ILogger<AlertDispatcherService> logger, IConfiguration configuration)
        {
            _http = http;
            _logger = logger;
            _endpoint = configuration["DashboardApi:BaseUrl"]
                ?? throw new InvalidOperationException("DashboardApi:BaseUrl is not configured.");
        }

        public async Task SendAsync(Alert alert)
        {
            try
            {
                var response = await _http.PostAsJsonAsync($"{_endpoint}/api/alerts", alert);

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

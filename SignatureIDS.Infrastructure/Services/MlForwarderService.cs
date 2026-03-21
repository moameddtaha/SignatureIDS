using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Configuration;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;

namespace SignatureIDS.Infrastructure.Services;

public class MlForwarderService : IMlForwarderService
{
    private readonly HttpClient _http;
    private readonly string _endpoint;

    public MlForwarderService(HttpClient http, IConfiguration configuration)
    {
        _http = http;
        _endpoint = configuration["ML:Endpoint"]
            ?? throw new InvalidOperationException("ML:Endpoint is not configured.");
    }

    public async Task<MlResult> ForwardAsync(string csv)
    {
        using var content = new StringContent(csv, Encoding.UTF8, "text/csv");
        using var response = await _http.PostAsync(_endpoint, content);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<MlResult>();
        return result ?? new MlResult { IsAttack = false };
    }
}

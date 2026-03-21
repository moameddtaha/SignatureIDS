using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

/// <summary>
/// Forwards a CSV-serialized flow feature row to the ML detection service and returns the prediction result.
/// </summary>
public interface IMlForwarderService
{
    /// <summary>
    /// Sends the CSV row to the ML service and returns the prediction.
    /// </summary>
    /// <param name="csv">A single CSV-formatted row produced by <see cref="ICsvSerializer"/>.</param>
    /// <returns>The ML model's prediction result.</returns>
    Task<MlResult> ForwardAsync(string csv);
}

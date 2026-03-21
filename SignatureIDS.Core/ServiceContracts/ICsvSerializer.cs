using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

/// <summary>
/// Serializes <see cref="FlowFeatures"/> into a CSV-formatted string for the ML service.
/// </summary>
public interface ICsvSerializer
{
    /// <summary>
    /// Serializes the given flow features into a single comma-separated row.
    /// </summary>
    /// <param name="features">The flow features to serialize.</param>
    /// <returns>A CSV row string with invariant-culture formatting.</returns>
    string WriteRow(FlowFeatures features);
}

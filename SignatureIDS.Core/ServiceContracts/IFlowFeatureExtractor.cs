using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

/// <summary>
/// Computes ML flow features from a window of captured packet headers.
/// </summary>
public interface IFlowFeatureExtractor
{
    /// <summary>
    /// Extracts aggregated flow features from the given packet window.
    /// </summary>
    /// <param name="headers">The list of packet headers in the current flow window.</param>
    /// <returns>A <see cref="FlowFeatures"/> instance ready to be serialized and forwarded to the ML service.</returns>
    FlowFeatures Extract(IReadOnlyList<PacketHeaders> headers);
}

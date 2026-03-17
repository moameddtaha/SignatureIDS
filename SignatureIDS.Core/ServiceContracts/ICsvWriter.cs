using SignatureIDS.Core.DTO.Detection;

namespace SignatureIDS.Core.ServiceContracts;

public interface ICsvWriter
{
    string WriteRow(FlowFeatures features);
    string WriteRows(IEnumerable<FlowFeatures> features);
}

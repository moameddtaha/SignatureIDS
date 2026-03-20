using SignatureIDS.Core.DTO.Detection;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.ServiceContracts
{
    public interface IMlInferenceService
    {
        MlResult Infer(FlowFeatures flowFeatures);
    }
}

using SignatureIDS.Core.DTO.Detection;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.ServiceContracts
{
    public interface IPacketCaptureService : IDisposable
    {
        void StartCapture(string interfaceName, Action<PacketHeaders> onPacker);
    }
}

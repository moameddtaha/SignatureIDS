using SignatureIDS.Core.DTO.Detection;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.ServiceContracts
{
    /// <summary>
    /// Captures live network packets from a specified network interface.
    /// </summary>
    public interface IPacketCaptureService : IDisposable
    {
        /// <summary>
        /// Starts capturing packets on the given network interface and invokes the callback for each captured packet.
        /// </summary>
        /// <param name="interfaceName">The name of the network interface to capture on.</param>
        /// <param name="onPacker">Callback invoked with the parsed headers of each captured packet.</param>
        void StartCapture(string interfaceName, Action<PacketHeaders> onPacker);
    }
}

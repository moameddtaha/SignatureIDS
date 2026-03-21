using System.Globalization;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;

namespace SignatureIDS.Infrastructure.Services;

public class CsvSerializer : ICsvSerializer
{
    private static readonly CultureInfo C = CultureInfo.InvariantCulture;

    public string WriteRow(FlowFeatures f)
    {
        return string.Join(',', new[]
        {
            // 0-3 Top-level
            f.HeaderLength.ToString(C),
            f.ProtocolType.ToString(C),
            f.TimeToLive.ToString(C),
            f.Rate.ToString("G4", C),          // 'G4' removes trailing zeros and uses '.' as decimal separator
                     //we can change it to 'F4' if we want to keep trailing zeros, but it will always use '.' as decimal separator regardless of locale        

            // 4-10 Flags
            f.FinFlagNumber.ToString(C),
            f.SynFlagNumber.ToString(C),
            f.RstFlagNumber.ToString(C),
            f.PshFlagNumber.ToString(C),
            f.AckFlagNumber.ToString(C),
            f.EceFlagNumber.ToString(C),
            f.CwrFlagNumber.ToString(C),

            // 11-25 Protocol indicators
            f.Http.ToString(C),
            f.Https.ToString(C),
            f.Dns.ToString(C),
            f.Telnet.ToString(C),
            f.Smtp.ToString(C),
            f.Ssh.ToString(C),
            f.Irc.ToString(C),
            f.Tcp.ToString(C),
            f.Udp.ToString(C),
            f.Dhcp.ToString(C),
            f.Arp.ToString(C),
            f.Icmp.ToString(C),
            f.Igmp.ToString(C),
            f.Ipv.ToString(C),
            f.Llc.ToString(C),

            // 26-33 Statistical aggregates
            f.TotSum.ToString("G4", C),
            f.Min.ToString("G4", C),
            f.Max.ToString("G4", C),
            f.Avg.ToString("G4", C),
            f.Std.ToString("G4", C),
            f.Iat.ToString("G4", C),
            f.Number.ToString(C),
            f.Variance.ToString("G4", C),

            // 34-35 Flow identifiers
            f.DestinationPort.ToString(C),
            f.ConnectionAttempts.ToString(C),

            // 36-45 Packet length features
            f.FwdPacketLengthMax.ToString("G4", C),
            f.FwdPacketLengthMin.ToString("G4", C),
            f.BwdPacketLengthMax.ToString("G4", C),
            f.BwdPacketLengthMin.ToString("G4", C),
            f.MinPacketLength.ToString("G4", C),
            f.MaxPacketLength.ToString("G4", C),
            f.FwdHeaderLength.ToString("G4", C),
            f.BwdHeaderLength.ToString("G4", C),
            f.InitWinBytesForward.ToString("G4", C),
            f.InitWinBytesBackward.ToString("G4", C),

            // 46 Backward PSH
            f.BwdPshFlags.ToString(C),

            // 47-57 Flow statistics
            f.FlowDuration.ToString("G4", C),
            f.TotalLengthOfFwdPackets.ToString("G4", C),
            f.TotalLengthOfBwdPackets.ToString("G4", C),
            f.FlowBytess.ToString("G4", C),
            f.FwdPacketss.ToString("G4", C),
            f.BwdPacketss.ToString("G4", C),
            f.AveragePacketSize.ToString("G4", C),
            f.FwdPacketLengthMean.ToString("G4", C),
            f.BwdPacketLengthMean.ToString("G4", C),
            f.PacketLengthMean.ToString("G4", C),
            f.ActDataPktFwd.ToString(C),

            // 58-59 ARP epsilon
            f.Epsilon1ArpReplyRatio.ToString("G4", C),
            f.Epsilon2SenderIpDensity.ToString("G4", C),
        });
    }
}
namespace SignatureIDS.Worker.Tests;

using SignatureIDS.Infrastructure.Services;
using SignatureIDS.Core.DTO.Detection;

public static class CsvWriterTests
{
    public static void Run()
    {
        var writer = new CsvWriter();

        // ── Test 1: column count ──────────────────────────────────────
        var f = new FlowFeatures
        {
            HeaderLength = 20,
            ProtocolType = 6,
            TimeToLive = 64,
            Rate = 100.5,
            FinFlagNumber = 0,
            SynFlagNumber = 1,
            RstFlagNumber = 0,
            PshFlagNumber = 0,
            AckFlagNumber = 1,
            EceFlagNumber = 0,
            CwrFlagNumber = 0,
            Http = 1,
            Https = 0,
            Dns = 0,
            Telnet = 0,
            Smtp = 0,
            Ssh = 0,
            Irc = 0,
            Tcp = 1,
            Udp = 0,
            Dhcp = 0,
            Arp = 0,
            Icmp = 0,
            Igmp = 0,
            Ipv = 0,
            Llc = 0,
            TotSum = 3000,
            Min = 40,
            Max = 1500,
            Avg = 500,
            Std = 200,
            Iat = 0.01,
            Number = 6,
            Variance = 40000,
            DestinationPort = 80,
            ConnectionAttempts = 1,
            FwdPacketLengthMax = 1500,
            FwdPacketLengthMin = 40,
            BwdPacketLengthMax = 800,
            BwdPacketLengthMin = 40,
            MinPacketLength = 40,
            MaxPacketLength = 1500,
            FwdHeaderLength = 20,
            BwdHeaderLength = 20,
            InitWinBytesForward = 65535,
            InitWinBytesBackward = 65535,
            BwdPshFlags = 0,
            FlowDuration = 0.5,
            TotalLengthOfFwdPackets = 2000,
            TotalLengthOfBwdPackets = 1000,
            FlowBytess = 6000,
            FwdPacketss = 8,
            BwdPacketss = 4,
            AveragePacketSize = 500,
            FwdPacketLengthMean = 666,
            BwdPacketLengthMean = 333,
            PacketLengthMean = 500,
            ActDataPktFwd = 3,
            Epsilon1ArpReplyRatio = 0,
            Epsilon2SenderIpDensity = 0,
        };

        var result = writer.WriteRow(f);
        var columns = result.Split(',');

        Console.WriteLine("=== Test 1: Column Count ===");
        Console.WriteLine($"Expected: 60 | Got: {columns.Length}");
        Console.WriteLine(columns.Length == 60 ? "PASS ✅" : "FAIL ❌");

        // ── Test 2: decimal separator is always '.' ───────────────────
        Console.WriteLine("\n=== Test 2: Decimal Separator ===");
        bool noCommaInDecimals = !result.Contains("100,5");
        Console.WriteLine(noCommaInDecimals ? "PASS ✅" : "FAIL ❌");

        // ── Test 3: correct values ────────────────────────────────────
        Console.WriteLine("\n=== Test 3: Spot Check Values ===");
        Console.WriteLine($"Col 0 (HeaderLength=20):     {columns[0]} → {(columns[0] == "20" ? "PASS ✅" : "FAIL ❌")}");
        Console.WriteLine($"Col 1 (ProtocolType=6):      {columns[1]} → {(columns[1] == "6"  ? "PASS ✅" : "FAIL ❌")}");
        Console.WriteLine($"Col 35 (DestinationPort=80): {columns[34]} → {(columns[34] == "80" ? "PASS ✅" : "FAIL ❌")}");
        Console.WriteLine($"Col 58 (ActDataPktFwd=3):    {columns[57]} → {(columns[57] == "3"  ? "PASS ✅" : "FAIL ❌")}");

        // ── Test 4: WriteRows ─────────────────────────────────────────
        Console.WriteLine("\n=== Test 4: WriteRows ===");
        var rows = writer.WriteRows(new[] { f, f });
        var lines = rows.Split(Environment.NewLine);
        Console.WriteLine($"Expected: 2 rows | Got: {lines.Length}");
        Console.WriteLine(lines.Length == 2 ? "PASS ✅" : "FAIL ❌");

        Console.WriteLine("\n=== Full Row ===");
        Console.WriteLine(result);
    }
}
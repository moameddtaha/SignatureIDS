using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.Domain.Entity
{
    public class Alert
    {
        public string Id { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int? Sid { get; set; }
        public string Msg { get; set; } = string.Empty;
        public string SrcIp { get; set; } = string.Empty;
        public string DstIp { get; set; } = string.Empty;
        public int? SrcPort { get; set; }
        public int? DstPort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string DetectionSource { get; set; } = string.Empty;
    }
}

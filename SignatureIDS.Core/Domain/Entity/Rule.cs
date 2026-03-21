using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.Domain.Entity
{
    public class Rule
    {
        public int Sid { get; set; }
        public string Msg { get; set; } = string.Empty;
        public string Proto { get; set; } = string.Empty;
        public string SrcPort { get; set; } = "any";
        public string DstPort { get; set; } = "any";
        public string? Content { get; set; }
        public bool? Nocase { get; set; }
        public bool? HttpUri { get; set; }
        public int Rev { get; set; }
        public string? Category { get; set; } = string.Empty;
        public bool? Enable { get; set; } = true;
    }
}

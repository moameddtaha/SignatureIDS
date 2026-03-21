using MongoDB.Driver;
using SignatureIDS.Core.Domain.Entity;
using SignatureIDS.Core.ServiceContracts;
using SignatureIDS.Core.ServiceContracts.Repositories;
using SignatureIDS.Infrastructure.Data;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace SignatureIDS.Infrastructure.Services
{
    public class RulesSyncService : IRulesSyncService
    {
        private readonly HttpClient _http;
        private readonly IRulesRepository _repo;
        private readonly MongoDbContext _context;

        private const string RulesUrl = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz";
        private const int SyncIntervalDays = 7;

        public RulesSyncService(HttpClient http, IRulesRepository repo, MongoDbContext context)
        {
            _http = http;
            _repo = repo;
            _context = context;
        }

        public async Task SyncNowAsync(CancellationToken ct = default)
        {
            var metadata = await _context.SyncMetadata
                .Find(m => m.Id == "rules_sync")
                .FirstOrDefaultAsync(ct);

            if (metadata is not null && (DateTime.UtcNow - metadata.LastSyncedAt).TotalDays < SyncIntervalDays)
                return;

            using var response = await _http.GetAsync(RulesUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            await using var compressed = await response.Content.ReadAsStreamAsync(ct);
            await using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
            using var tar = new TarReader(gzip);

            var batch = new List<Rule>(500);

            TarEntry? entry;
            while((entry = await tar.GetNextEntryAsync(copyData: false, ct)) != null)
            {
                if (entry.EntryType != TarEntryType.RegularFile || !entry.Name.EndsWith(".rules")) continue;
                if(!entry.Name.EndsWith(".rules", StringComparison.OrdinalIgnoreCase)) continue;
                if (entry.DataStream is null) continue;

                using var reader = new StreamReader(entry.DataStream, Encoding.UTF8);
                string? line;
                while((line = await reader.ReadLineAsync(ct)) is not null)
                {
                    var rule = ParseRule(line);
                    if(rule is null) continue;

                    batch.Add(rule);

                    if(batch.Count == 500)
                    {
                        await _repo.BulkUpsertAsync(batch);
                        batch.Clear();
                    }
                }
            }

            if (batch.Count > 0)
                await _repo.BulkUpsertAsync(batch);

            await _context.SyncMetadata.ReplaceOneAsync(
                m => m.Id == "rules_sync",
                new SyncMetadata { Id = "rules_sync", LastSyncedAt = DateTime.UtcNow },
                new ReplaceOptions { IsUpsert = true },
                ct);
        }

        private static Rule? ParseRule(string line)
        {
            line = line.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#')) return null;
            if (!line.StartsWith("alert")) return null;

            var sidMatch = Regex.Match(line, @"\bsid\s*:\s*(\d+)\s*;");
            if (!sidMatch.Success) return null;
            int sid = int.Parse(sidMatch.Groups[1].Value);

            var msgMatch = Regex.Match(line, @"\bmsg\s*:\s*""([^""]+)""");
            string msg = msgMatch.Success ? msgMatch.Groups[1].Value : string.Empty;

            var headerMatch = Regex.Match(line, @"^alert\s+(\w+)\s+\S+\s+(\S+)\s+->\s+\S+\s+(\S+)");
            string proto   = headerMatch.Success ? headerMatch.Groups[1].Value : string.Empty;
            string srcPort = headerMatch.Success ? headerMatch.Groups[2].Value : "any";
            string dstPort = headerMatch.Success ? headerMatch.Groups[3].Value : "any";

            var contentMatch = Regex.Match(line, @"\bcontent\s*:\s*""([^""]+)""");
            string? content = contentMatch.Success ? contentMatch.Groups[1].Value : null;

            bool nocase  = Regex.IsMatch(line, @"\bnocase\s*;");
            bool httpUri = Regex.IsMatch(line, @"\bhttp_uri\s*;");

            var revMatch = Regex.Match(line, @"\brev\s*:\s*(\d+)\s*;");
            int rev = revMatch.Success ? int.Parse(revMatch.Groups[1].Value) : 0;

            var classtypeMatch = Regex.Match(line, @"\bclasstype\s*:\s*([\w-]+)\s*;");
            string? category = classtypeMatch.Success ? classtypeMatch.Groups[1].Value : null;

            return new Rule
            {
                Sid      = sid,
                Msg      = msg,
                Proto    = proto,
                SrcPort  = srcPort,
                DstPort  = dstPort,
                Content  = content,
                Nocase   = nocase   ? true : null,
                HttpUri  = httpUri  ? true : null,
                Rev      = rev,
                Category = category,
                Enable   = true
            };
        }
    }
}

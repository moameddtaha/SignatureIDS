using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SignatureIDS.Core.Domain.Entity;
using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;
using SignatureIDS.Core.ServiceContracts.Repositories;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Infrastructure.Services
{
    public class SignatureDetectionService : ISignatureDetectionService
    {
        private const string CacheKey = "rules";
        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(30);

        private readonly IRulesRepository _repository;
        private readonly IMemoryCache _cache;
        private readonly ILogger<SignatureDetectionService> _logger;

        public SignatureDetectionService(IRulesRepository repository, IMemoryCache cache, ILogger<SignatureDetectionService> logger)
        {
            _repository = repository;
            _cache = cache;
            _logger = logger;
        }

        public async Task<DetectionResult?> DetectAsync(PacketHeaders packet)
        {
            var rules = await GetRulesAsync();

            foreach (var rule in rules)
            {
                if (!MatchesProtocol(rule, packet)) continue;
                if(!MatchesPort(rule, packet)) continue;
                if(!MatchesContent(rule, packet)) continue;

                return new DetectionResult
                {
                    IsMatch = true,
                    MatchedRule = rule
                };
            }

            return null;
        }

        private async Task<List<Rule>> GetRulesAsync()
        {
            if (_cache.TryGetValue(CacheKey, out List<Rule>? rules) && rules is not null)
            {
                _logger.LogDebug("Rules retrieved from cache.");
                return rules;
            }
            _logger.LogInformation("Rules not found in cache. Fetching from repository...");
            rules = await _repository.GetAllEnabledAsync();
            _cache.Set(CacheKey, rules, CacheTtl);
            _logger.LogInformation("Rules cached for {CacheTtl} minutes.", CacheTtl.TotalMinutes);
            return rules;
        }

        private static bool MatchesProtocol(Rule rule, PacketHeaders packet)
        {
            if (rule.Proto == "any") return true;
            return string.Equals(rule.Proto, packet.Protocol, StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchesPort(Rule rule, PacketHeaders packet)
        {
            if (rule.DstPort == "any") return true;

            if(rule.DstPort.Contains(':'))
            {
                var parts = rule.DstPort.Split(':');
                if (parts.Length != 2) return false;
                if (!int.TryParse(parts[0], out int startPort)) return false;
                if (!int.TryParse(parts[1], out int endPort)) return false;
                return packet.DstPort is not null && packet.DstPort >= startPort && packet.DstPort <= endPort;
            }

            if (!int.TryParse(rule.DstPort, out int rulePort)) return false;
            return packet.DstPort == rulePort;
        }

        private static bool MatchesContent(Rule rule, PacketHeaders packet)
        {
            if (rule.Content is null) return true;
            var payload = Encoding.Latin1.GetString(packet.Payload);

            return rule.Nocase == true
                ? payload.Contains(rule.Content, StringComparison.OrdinalIgnoreCase)
                : payload.Contains(rule.Content, StringComparison.Ordinal);
        }
    }
}
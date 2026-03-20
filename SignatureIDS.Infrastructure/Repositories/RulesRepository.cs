using MongoDB.Driver;
using SignatureIDS.Core.Domain.Entity;
using SignatureIDS.Core.ServiceContracts.Repositories;
using SignatureIDS.Infrastructure.Data;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Infrastructure.Repositories
{
    public class RulesRepository : IRulesRepository
    {
        private readonly IMongoCollection<Rule> _rules;

        public RulesRepository(MongoDbContext context)
        {
            _rules = context.Rules;
        }

        public async Task DisableAsync(int sid)
        {
            var Update = Builders<Rule>.Update.Set(r => r.Enable, false);
            await _rules.UpdateOneAsync(r => r.Sid == sid, Update);
        }

        public async Task<List<Rule>> GetAllEnabledAsync()
        {
            return await _rules
                .Find(r => r.Enable == true)
                .ToListAsync();
        }

        public async Task<Rule?> GetBySidAsync(int sid)
        {
            return await _rules
                .Find(r => r.Sid == sid)
                .FirstOrDefaultAsync();
        }

        public async Task UpsertAsync(Rule rule)
        {
            await _rules.ReplaceOneAsync(
                r => r.Sid == rule.Sid,
                rule,
                new ReplaceOptions { IsUpsert = true });
        }
    }
}

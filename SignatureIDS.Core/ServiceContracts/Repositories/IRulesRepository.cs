using System;
using System.Collections.Generic;
using System.Text;
using SignatureIDS.Core.Domain.Entity;

namespace SignatureIDS.Core.ServiceContracts.Repositories
{
    public interface IRulesRepository
    {
        Task<List<Rule>> GetAllEnabledAsync();
        Task<Rule?> GetBySidAsync(int sid);
        Task UpsertAsync(Rule rule);
        Task DisableAsync(int sid);
    }
}

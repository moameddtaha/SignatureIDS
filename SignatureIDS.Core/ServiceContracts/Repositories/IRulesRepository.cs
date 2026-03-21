using System;
using System.Collections.Generic;
using System.Text;
using SignatureIDS.Core.Domain.Entity;

namespace SignatureIDS.Core.ServiceContracts.Repositories
{
    /// <summary>
    /// Provides data access operations for IDS rules stored in the database.
    /// </summary>
    public interface IRulesRepository
    {
        /// <summary>
        /// Returns all rules that are currently enabled.
        /// </summary>
        Task<List<Rule>> GetAllEnabledAsync();

        /// <summary>
        /// Returns the rule with the given Snort ID, or <c>null</c> if not found.
        /// </summary>
        /// <param name="sid">The Snort rule ID.</param>
        Task<Rule?> GetBySidAsync(int sid);

        /// <summary>
        /// Inserts the rule if it does not exist, or updates it if it does.
        /// </summary>
        /// <param name="rule">The rule to insert or update.</param>
        Task UpsertAsync(Rule rule);

        /// <summary>
        /// Inserts or updates a batch of rules in a single database operation.
        /// </summary>
        /// <param name="rules">The rules to insert or update.</param>
        Task BulkUpsertAsync(IEnumerable<Rule> rules);

        /// <summary>
        /// Marks the rule with the given Snort ID as disabled.
        /// </summary>
        /// <param name="sid">The Snort rule ID to disable.</param>
        Task DisableAsync(int sid);
    }
}

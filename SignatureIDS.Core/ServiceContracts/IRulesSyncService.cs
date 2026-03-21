using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.ServiceContracts
{
    /// <summary>
    /// Synchronizes IDS rules from the remote source into the local database.
    /// </summary>
    public interface IRulesSyncService
    {
        /// <summary>
        /// Pulls the latest rules from the remote source and updates the local database.
        /// </summary>
        /// <param name="ct">Token to cancel the operation.</param>
        Task SyncNowAsync(CancellationToken ct = default);
    }
}

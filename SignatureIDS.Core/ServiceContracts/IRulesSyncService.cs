using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Core.ServiceContracts
{
    public interface IRulesSyncService
    {
        Task SyncNowAsync(CancellationToken ct = default);
    }
}

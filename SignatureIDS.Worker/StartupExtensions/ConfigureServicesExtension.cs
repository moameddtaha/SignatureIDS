using SignatureIDS.Core.ServiceContracts;
using SignatureIDS.Core.ServiceContracts.Repositories;
using SignatureIDS.Infrastructure.Data;
using SignatureIDS.Infrastructure.Repositories;
using SignatureIDS.Infrastructure.Services;

namespace SignatureIDS.Worker.StartupExtensions
{
    public static class ConfigureServicesExtension
    {
        public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
        {
            // ========================================
            // CACHE
            // ========================================
            services.AddMemoryCache();

            // ========================================
            // MONGODB
            // ========================================
            services.AddSingleton<MongoDbContext>();

            // ========================================
            // REPOSITORIES
            // ========================================
            services.AddSingleton<IRulesRepository, RulesRepository>();

            // ========================================
            // HTTP CLIENTS
            // ========================================
            services.AddHttpClient<IRulesSyncService, RulesSyncService>();
            services.AddHttpClient<IAlertDispatcherService, AlertDispatcherService>();
            services.AddHttpClient<IMlForwarderService, MlForwarderService>();

            // ========================================
            // SERVICES
            // ========================================
            services.AddSingleton<IPacketCaptureService, PacketCaptureService>();
            services.AddSingleton<ISignatureDetectionService, SignatureDetectionService>();
            services.AddSingleton<IFlowFeatureExtractor, FlowFeatureExtractor>();
            services.AddSingleton<ICsvSerializer, CsvSerializer>();

            // ========================================
            // WORKER
            // ========================================
            services.AddHostedService<Worker>();
        }
    }
}

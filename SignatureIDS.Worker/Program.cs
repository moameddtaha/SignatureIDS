using DotNetEnv;
using Serilog;
using SignatureIDS.Worker;
using SignatureIDS.Worker.StartupExtensions;

Env.Load();

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/signatureids-.log", rollingInterval: RollingInterval.Day)
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting SignatureIDS Worker...");

    var builder = Host.CreateApplicationBuilder(args);

    builder.Services.AddSerilog((services, config) => config
        .ReadFrom.Services(services)
        .WriteTo.Console()
        .WriteTo.File("logs/signatureids-.log", rollingInterval: RollingInterval.Day));

    builder.Services.ConfigureServices(builder.Configuration);

    var host = builder.Build();
    host.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Worker terminated unexpectedly.");
}
finally
{
    Log.CloseAndFlush();
}
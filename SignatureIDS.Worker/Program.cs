using SignatureIDS.Worker;
using SignatureIDS.Worker.StartupExtensions;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.ConfigureServices(builder.Configuration);

var host = builder.Build();
host.Run();
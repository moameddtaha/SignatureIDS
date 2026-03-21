








using SignatureIDS.Worker;

SignatureIDS.Worker.Tests.CsvWriterTests.Run();



var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();






using RdpGuard;
using RdpGuard.Options;
using RdpGuard.Services;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "RdpGuard";
});

builder.Services.Configure<RdpGuardOptions>(builder.Configuration.GetSection("RdpGuard"));
builder.Services.AddSingleton<FileLogger>();
builder.Services.AddSingleton<StateStore>();
builder.Services.AddSingleton<FirewallManager>();
builder.Services.AddSingleton<AttackDetector>();
builder.Services.AddSingleton<StatisticsTracker>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();

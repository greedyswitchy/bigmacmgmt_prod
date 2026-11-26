using System.Threading.Channels;
using ArmDeviceAgent;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "ArmDeviceMonitorAgent";
});

builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection("AgentConfig"));

builder.Services.AddSingleton(_ => Channel.CreateUnbounded<RawPnpEvent>(new UnboundedChannelOptions
{
    SingleReader = true,
    SingleWriter = false
}));

builder.Services.AddSingleton<SqliteBatchQueue>();

builder.Services.AddHttpClient("BackendClient", (sp, client) =>
{
    var opts = sp.GetRequiredService<IOptions<AgentOptions>>().Value;
    client.Timeout = TimeSpan.FromSeconds(10);
    if (!string.IsNullOrWhiteSpace(opts.ApiKey))
    {
        client.DefaultRequestHeaders.Add("X-Api-Key", opts.ApiKey);
    }
});

builder.Services.AddHostedService<PnpMonitorService>();
builder.Services.AddHostedService<BatchDispatcherWorker>();

var host = builder.Build();
host.Run();
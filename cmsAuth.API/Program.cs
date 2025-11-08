using cmsAuth.Application.Interfaces;
using cmsAuth.Infrastructure.Persistance;
using cmsAuth.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString))
);

var redisConnection = builder.Configuration.GetValue<string>("Redis:Connection");
if (string.IsNullOrWhiteSpace(redisConnection))
    throw new InvalidOperationException("Redis connection string is not configured (Redis:Connection).");

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisConnection;
    options.InstanceName = "auth:";
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();

builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

var app = builder.Build();

// Optional: verify Redis is reachable at startup
using (var scope = app.Services.CreateScope())
{
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    try
    {
        var cache = scope.ServiceProvider.GetRequiredService<IDistributedCache>();
        var probeKey = "auth:probe:" + Guid.NewGuid().ToString("N");
        cache.SetString(probeKey, "ok", new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(10) });
        var v = cache.GetString(probeKey);
        if (v != "ok") logger.LogWarning("Redis probe failed: value mismatch");
        else logger.LogInformation("Redis probe succeeded");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Redis connectivity probe failed. Check Redis:Connection and network reachability.");
        throw;
    }
}

app.UseHttpsRedirection();
app.MapControllers();
app.Run();

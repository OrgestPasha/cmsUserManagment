using System.Text.Json;
using cmsAuth.Application.DTO;
using cmsAuth.Application.Interfaces;
using cmsAuth.Infrastructure.Persistance;
using Microsoft.Extensions.Caching.Distributed;

namespace cmsAuth.Infrastructure.Repositories;

public class AuthenticationService(AppDbContext context, IDistributedCache cache) : IAuthenticationService
{
    private readonly AppDbContext _context = context;
    private readonly IDistributedCache _cache = cache;
    private const string CachePrefix = "user:";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string UserCacheKey(string email) => $"{CachePrefix}{email.ToLowerInvariant()}";

    public object? Login(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email)) throw new ArgumentException("email is required", nameof(email));

        var cacheKey = UserCacheKey(email);
        var cachedJson = _cache.GetString(cacheKey);

        if (string.IsNullOrEmpty(cachedJson))
        {
            // In a real app, fallback to DB here, then cache. For now, return 404-like message.
            return "User not found in cache";
        }

        var user = JsonSerializer.Deserialize<RegisterUser>(cachedJson, JsonOptions);
        return user;
    }

    public object? Register(RegisterUser user)
    {
        if (user is null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrWhiteSpace(user.Email)) throw new ArgumentException("Email is required", nameof(user.Email));

        var cacheKey = UserCacheKey(user.Email);
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(96)
        };

        // Save to Redis
        var json = JsonSerializer.Serialize(user, JsonOptions);
        _cache.SetString(cacheKey, json, options);

        // Verify retrieval
        var cachedJson = _cache.GetString(cacheKey);
        if (string.IsNullOrEmpty(cachedJson))
        {
            throw new InvalidOperationException("Failed to cache user");
        }

        return JsonSerializer.Deserialize<RegisterUser>(cachedJson, JsonOptions);
    }

    public string RefreshToken(string token)
    {
        throw new NotImplementedException();
    }

    public void Logout(string token)
    {
        throw new NotImplementedException();
    }
}
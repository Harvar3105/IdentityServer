using System.Security.Claims;
using System.Text;
using IdentityServer.Entities;
using IdentityServer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Tests.Unit.Services;

// SQLite in-memory instead of the EF InMemory provider: TokenService relies on ExecuteUpdateAsync and
// transactions, which the InMemory provider does not support.
public sealed class TokenServiceFixture : IAsyncDisposable
{
  public const string Issuer = "test-issuer";
  public const string Audience = "test-audience";
  // At least 64 bytes so that tests can also sign with HS512 using the same key.
  public const string Secret = "test-secret-key-that-is-long-enough-for-hmac-sha256-and-sha512-signatures";
  public const int AccessTokenExpirationMinutes = 15;
  public const int RefreshTokenExpirationDays = 7;
  public const string IpAddress = "127.0.0.1";

  private readonly SqliteConnection _connection;
  private readonly ServiceProvider _rootProvider;
  private readonly AsyncServiceScope _scope;

  public TokenValidationParameters ValidationParameters { get; }
  public TokenService TokenService { get; }
  public UserManager<User> UserManager { get; }
  public RoleManager<Role> RoleManager { get; }
  public ApplicationDbContext DbContext { get; }

  private TokenServiceFixture(int accessTokenExpirationMinutes)
  {
    _connection = new SqliteConnection("DataSource=:memory:");
    _connection.Open();

    ValidationParameters = CreateValidationParameters(Secret);

    var config = new ConfigurationBuilder()
      .AddInMemoryCollection(new Dictionary<string, string?>
      {
        ["Security:JWTExpiration"] = accessTokenExpirationMinutes.ToString(),
        ["Security:RTExpiration"] = RefreshTokenExpirationDays.ToString(),
      })
      .Build();

    var services = new ServiceCollection();
    services.AddLogging();
    services.AddSingleton<IConfiguration>(config);
    services.AddSingleton(ValidationParameters);
    services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_connection));
    services.AddIdentityCore<User>()
      .AddRoles<Role>()
      .AddEntityFrameworkStores<ApplicationDbContext>();
    services.AddScoped<TokenService>();

    _rootProvider = services.BuildServiceProvider();
    _scope = _rootProvider.CreateAsyncScope();

    DbContext = _scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    DbContext.Database.EnsureCreated();

    TokenService = _scope.ServiceProvider.GetRequiredService<TokenService>();
    UserManager = _scope.ServiceProvider.GetRequiredService<UserManager<User>>();
    RoleManager = _scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
  }

  public static TokenServiceFixture Create(int accessTokenExpirationMinutes = AccessTokenExpirationMinutes)
  {
    return new TokenServiceFixture(accessTokenExpirationMinutes);
  }

  public static TokenValidationParameters CreateValidationParameters(string secret)
  {
    return new TokenValidationParameters
    {
      RoleClaimType = ClaimTypes.Role,
      NameClaimType = ClaimTypes.Name,
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateIssuerSigningKey = true,
      ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
      ValidIssuer = Issuer,
      ValidAudience = Audience,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
      ClockSkew = TimeSpan.FromMinutes(1)
    };
  }

  public async Task<User> CreateUserAsync(string userName = "alice", params string[] roles)
  {
    var user = new User { UserName = userName, Email = $"{userName}@example.com" };
    var result = await UserManager.CreateAsync(user);
    Assert.True(result.Succeeded, result.ToString());

    foreach (var role in roles)
    {
      if (!await RoleManager.RoleExistsAsync(role))
        Assert.True((await RoleManager.CreateAsync(new Role { Name = role })).Succeeded);
    }

    if (roles.Length > 0)
      Assert.True((await UserManager.AddToRolesAsync(user, roles)).Succeeded);

    return user;
  }

  public async Task<(RefreshToken entity, string rawToken)> AddRefreshTokenAsync(User user)
  {
    var (entity, rawToken) = TokenService.GenerateRefreshToken(IpAddress, user);
    DbContext.RefreshTokens.Add(entity);
    await DbContext.SaveChangesAsync();
    return (entity, rawToken);
  }

  // ExecuteUpdateAsync bypasses the change tracker, so assertions read the persisted state untracked.
  public Task<RefreshToken> ReloadRefreshTokenAsync(Guid id)
  {
    return DbContext.RefreshTokens.AsNoTracking().SingleAsync(rt => rt.Id == id);
  }

  public async Task<string?> GetPersistedSecurityStampAsync(Guid userId)
  {
    return (await DbContext.Users.AsNoTracking().SingleAsync(u => u.Id == userId)).SecurityStamp;
  }

  // Production uses a scoped DbContext per request; entities tracked by an earlier "request" would hide the
  // changes made by ExecuteUpdateAsync, which bypasses the change tracker.
  public void StartNewRequest()
  {
    DbContext.ChangeTracker.Clear();
  }

  public async ValueTask DisposeAsync()
  {
    await _scope.DisposeAsync();
    await _rootProvider.DisposeAsync();
    await _connection.DisposeAsync();
  }
}

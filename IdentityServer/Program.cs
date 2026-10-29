using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using IdentityServer;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using IdentityServer.Middleware;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
{
  builder.Configuration.SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.Development.json", optional: false, reloadOnChange: true);
}
else
{
  builder.Configuration.SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
}

// Roles are required in every environment (registration assigns Roles:Initial), so the file may be replaced
// by Roles__* environment variables; seeded users are development data only.
builder.Configuration.AddJsonFile("Seed/roles.json", optional: true, reloadOnChange: false);
if (builder.Environment.IsDevelopment())
{
  builder.Configuration.AddJsonFile("Seed/users.json", optional: true, reloadOnChange: false);
}

builder.Configuration.AddEnvironmentVariables();
builder.Services.AddOpenApi();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var lockoutMaxFailedAttempts = builder.Configuration.GetValue<int?>("Security:LockoutMaxFailedAttempts")
  ?? throw new InvalidOperationException("Security:LockoutMaxFailedAttempts is not configured.");
var lockoutDuration = TimeSpan.FromMinutes(
  builder.Configuration.GetValue<int?>("Security:LockoutDurationMinutes")
  ?? throw new InvalidOperationException("Security:LockoutDurationMinutes is not configured."));
var lockoutAllowedForNewUsers = builder.Configuration.GetValue<bool?>("Security:LockoutAllowedForNewUsers")
  ?? throw new InvalidOperationException("Security:LockoutAllowedForNewUsers is not configured.");

var passwordPolicySection = builder.Configuration.GetSection("Security:Password");
if (!passwordPolicySection.Exists())
  throw new InvalidOperationException("Security:Password is not configured.");

builder.Services.AddIdentity<User, Role>(options =>
  {
    passwordPolicySection.Bind(options.Password);

    options.Lockout.AllowedForNewUsers = lockoutAllowedForNewUsers;
    options.Lockout.MaxFailedAccessAttempts = lockoutMaxFailedAttempts;
    options.Lockout.DefaultLockoutTimeSpan = lockoutDuration;
  })
  .AddEntityFrameworkStores<ApplicationDbContext>()
  .AddDefaultTokenProviders();

builder.Services.AddScoped<ITokenService, TokenService>();

var credentialRateLimitPermits = builder.Configuration.GetValue<int?>("Security:CredentialRateLimitPermits")
  ?? throw new InvalidOperationException("Security:CredentialRateLimitPermits is not configured.");
var credentialRateLimitWindow = TimeSpan.FromSeconds(
  builder.Configuration.GetValue<int?>("Security:CredentialRateLimitWindowSeconds")
  ?? throw new InvalidOperationException("Security:CredentialRateLimitWindowSeconds is not configured."));

// Lockout protects a single account; the per-IP limit also covers password spraying across many accounts.
builder.Services.AddRateLimiter(options =>
{
  options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
  options.AddPolicy(RateLimitPolicies.CredentialEndpoints, httpContext =>
    // TODO: Behind a reverse proxy RemoteIpAddress is the proxy address; configure ForwardedHeaders first.
    RateLimitPartition.GetFixedWindowLimiter(
      partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
      factory: _ => new FixedWindowRateLimiterOptions
      {
        PermitLimit = credentialRateLimitPermits,
        Window = credentialRateLimitWindow,
        QueueLimit = 0
      }));
});

var twp = new TokenValidationParameters
{
  RoleClaimType = ClaimTypes.Role,
  NameClaimType = ClaimTypes.Name,
  ValidateIssuer = true,
  ValidateAudience = true,
  ValidateIssuerSigningKey = true,
  ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
  ValidIssuer = builder.Configuration.GetValue<string>("Security:JWTIssuer"),
  ValidAudience = builder.Configuration.GetValue<string>("Security:JWTAudience"),
  IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
        builder.Configuration.GetValue<string>("Security:JWTSecret")!
    )),
  ClockSkew = TimeSpan.FromMinutes(1)
};
builder.Services.AddSingleton(twp);

// AddIdentity sets cookie authentication as the default authenticate/challenge scheme,
// which takes precedence over DefaultScheme, so JWT has to override them explicitly.
builder.Services.AddAuthentication(options =>
  {
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
  })
    .AddJwtBearer(options => { options.TokenValidationParameters = twp; });
builder.Services.AddAuthorization();

// FIXME: [Important] Any origin is allowed; restrict to the origins of registered client projects.
builder.Services.AddCors(options =>
{
  options.AddPolicy("AllowAll", policy =>
  {
    policy.AllowAnyOrigin()
          .AllowAnyHeader()
          .AllowAnyMethod();
  });
});

builder.Services.AddControllers();

if (builder.Environment.IsDevelopment())
{
  builder.Services.AddEndpointsApiExplorer();
  builder.Services.AddSwaggerGen();
}

builder.Services.Configure<SeedSettings>(
  builder.Configuration.GetSection("Seed")
);
builder.Services.AddOptions<RoleSettings>()
  .Bind(builder.Configuration.GetSection("Roles"))
  .Validate(roles => roles.IsAvailable(roles.Initial), "Roles:Initial must be listed in Roles:Available.")
  .Validate(roles => roles.IsAvailable(roles.Root), "Roles:Root must be listed in Roles:Available.")
  .Validate(roles => roles.Managers.All(roles.IsAvailable), "Every Roles:Managers entry must be listed in Roles:Available.")
  .Validate(roles => !roles.IsPrivileged(roles.Initial), "Roles:Initial must not be the root or a manager role.")
  .ValidateOnStart();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
  app.UseMiddleware<RequestLoggingMiddleware>();
  app.MapOpenApi();
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseRouting();
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// FIXME: [Important] HTTPS redirection and CORS must run before authentication/authorization;
// CORS preflight requests to [Authorize] endpoints fail with the current order.
app.UseHttpsRedirection();

app.UseCors("AllowAll");

SetupAppData(app);

app.Run();


static void SetupAppData(WebApplication app)
{
  using var serviceScope = ((IApplicationBuilder)app).ApplicationServices
      .GetRequiredService<IServiceScopeFactory>()
      .CreateScope();
  using var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

  if (!context.Database.ProviderName!.Contains("InMemory"))
  {
    context.Database.Migrate();
  }

  using var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();
  using var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
  var seedSettings = serviceScope.ServiceProvider
    .GetRequiredService<IOptions<SeedSettings>>()
    .Value;
  var roleSettings = serviceScope.ServiceProvider
    .GetRequiredService<IOptions<RoleSettings>>()
    .Value;

  foreach (var role in roleSettings.Available)
  {
    var exists = roleManager.FindByNameAsync(role).Result;
    if (exists is not null) continue;

    var result = roleManager.CreateAsync(new Role()
    {
      Name = role
    }).Result;
    if (!result.Succeeded) Console.WriteLine(result.ToString());
  }

  if (!app.Environment.IsDevelopment()) return;

  foreach (var seedUser in seedSettings.Users)
  {
    var unknownRoles = seedUser.Roles.Where(role => !roleSettings.IsAvailable(role)).ToList();
    if (unknownRoles.Count > 0)
    {
      Console.WriteLine($"Seed user {seedUser.Email} skipped: roles {string.Join(", ", unknownRoles)} are not listed in Roles:Available.");
      continue;
    }

    var user = userManager.FindByEmailAsync(seedUser.Email).Result;
    if (user is null)
    {
      user = new User { Email = seedUser.Email, UserName = seedUser.Username };
      var creationResult = userManager.CreateAsync(user, seedUser.Password).Result;
      if (!creationResult.Succeeded)
      {
        Console.WriteLine($"Seed user {seedUser.Email} not created: {creationResult}");
        continue;
      }
    }

    var currentRoles = userManager.GetRolesAsync(user).Result;
    var missingRoles = seedUser.Roles.Except(currentRoles, StringComparer.OrdinalIgnoreCase).ToList();
    var extraRoles = currentRoles.Except(seedUser.Roles, StringComparer.OrdinalIgnoreCase).ToList();

    if (missingRoles.Count > 0)
    {
      var addResult = userManager.AddToRolesAsync(user, missingRoles).Result;
      if (!addResult.Succeeded) Console.WriteLine($"Seed user {seedUser.Email} roles not added: {addResult}");
    }

    if (extraRoles.Count > 0)
    {
      var removeResult = userManager.RemoveFromRolesAsync(user, extraRoles).Result;
      if (!removeResult.Succeeded) Console.WriteLine($"Seed user {seedUser.Email} roles not removed: {removeResult}");
    }
  }
}

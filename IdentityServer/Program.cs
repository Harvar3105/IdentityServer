using System.Security.Claims;
using System.Text;
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
builder.Configuration.AddEnvironmentVariables();
builder.Services.AddOpenApi();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<User, Role>(options =>
  {
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 4;
    options.Password.RequiredUniqueChars = 0;
  })
  .AddEntityFrameworkStores<ApplicationDbContext>()
  .AddDefaultTokenProviders();

builder.Services.AddScoped<ITokenService, TokenService>();

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

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => { options.TokenValidationParameters = twp; });
builder.Services.AddAuthorization();

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
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Configuration.AddJsonFile(
  "Seed/seedsettings.json",
  optional: false,
  reloadOnChange: false
);
builder.Services.Configure<SeedSettings>(
  builder.Configuration.GetSection("Seed")
);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
  app.UseMiddleware<RequestLoggingMiddleware>();
  app.MapOpenApi();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

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

  string[] roles = seedSettings.Projects.Select(p => p.Roles).SelectMany(r => r.Admin.Concat(r.User)).Distinct().ToArray();
  foreach (var role in roles)
  {
    var exists = roleManager.FindByNameAsync(role).Result;
    if (exists is not null) continue;

    var result = roleManager.CreateAsync(new Role()
    {
      Name = role
    }).Result;
    if (!result.Succeeded) Console.WriteLine(result.ToString());
  }

  foreach (var user in seedSettings.Users)
  {
    var parsed = new User()
    {
      Email = user.Email,
      UserName = user.Username,
    };

    var existingUser = userManager.FindByEmailAsync(user.Email).Result;

    if (existingUser is null)
    {
      var registration = userManager.CreateAsync(parsed, user.Password).Result;
      if (!registration.Succeeded) Console.WriteLine(registration.ToString());
      existingUser = userManager.FindByEmailAsync(parsed.Email).Result;
    }
    
    var userRoles = userManager.GetRolesAsync(existingUser!).Result;
    if (!userRoles.OrderBy(r => r).SequenceEqual(user.Roles.OrderBy(r => r)))
    {
      var registration = userManager.AddToRolesAsync(parsed, user.Roles).Result;
      if (!registration.Succeeded) Console.WriteLine(registration.ToString());
    }
  }
}

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityServer;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
    ValidIssuer = builder.Configuration.GetValue<string>("Security:JWTIssuer"),
    ValidAudience = builder.Configuration.GetValue<string>("Security:JWTAudience"),
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
        builder.Configuration.GetValue<string>("Security:JWTSecret")!
    )),
    ClockSkew = TimeSpan.Zero
};
builder.Services.AddSingleton(twp);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {options.TokenValidationParameters = twp;});
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


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();
app.UseAuthorization();
app.MapControllers(); 

app.UseHttpsRedirection();

app.UseCors("AllowAll");

SetupAppData(app);

app.Run();


static void SetupAppData(WebApplication app)
{
    using var serviceScope = ((IApplicationBuilder) app).ApplicationServices
        .GetRequiredService<IServiceScopeFactory>()
        .CreateScope();
    using var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    if (!context.Database.ProviderName!.Contains("InMemory"))
    {
        context.Database.Migrate();
    }


    using var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();
    using var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

    var res = roleManager.CreateAsync(new Role()
    {
        Name = "Admin"
    }).Result;

    if (!res.Succeeded)
    {
        Console.WriteLine(res.ToString());
    }

    var res2 = roleManager.CreateAsync(new Role()
    {
        Name = "User"
    }).Result;

    if (!res2.Succeeded)
    {
        Console.WriteLine(res2.ToString());
    }

    var user = new User()
    {
        Email = "admin@eesti.ee",
        UserName = "admin@eesti.ee",
        FirstName = "Admin",
        LastName = "Admin",
    };
    res = userManager.CreateAsync(user, "Kala.maja1").Result;
    if (!res.Succeeded)
    {
        Console.WriteLine(res.ToString());
    }
    var user2 = new User()
    {
        Email = "bob@eesti.ee",
        UserName = "bob@eesti.ee",
        FirstName = "Bob",
        LastName = "Bober",
    };
    res = userManager.CreateAsync(user2, "Kala.maja2").Result;
    if (!res.Succeeded)
    {
        Console.WriteLine(res.ToString());
    }

    res = userManager.AddToRoleAsync(user, "Admin").Result;
    if (!res.Succeeded)
    {
        Console.WriteLine(res.ToString());
    }
}
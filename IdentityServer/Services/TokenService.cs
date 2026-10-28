using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Services;

public class TokenService : ITokenService
{
  private readonly IConfiguration _config;
  private readonly TokenValidationParameters _twp;
  private readonly JwtSecurityTokenHandler _tokenHandler = new();
  private readonly UserManager<User> _userManager;
  private readonly ApplicationDbContext _dbContext;
  private readonly ILogger<TokenService> _logger;

  public TokenService(IConfiguration config, TokenValidationParameters twp, UserManager<User> userManager, ApplicationDbContext dbContext, ILogger<TokenService> logger)
  {
    _config = config;
    _twp = twp;
    _userManager = userManager;
    _dbContext = dbContext;
    _logger = logger;
  }

  public async Task<string> GenerateAccessToken(User user)
  {
    var claims = new List<Claim>
    {
      new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
      new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
      new Claim(ClaimTypes.Name, user.UserName!),
    };

    // FIXME: [Important] Roles are global and not scoped per project: equally named roles grant access across projects.
    var roles = await _userManager.GetRolesAsync(user);
    claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

    var key = _twp.IssuerSigningKey;
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("Security:JWTExpiration"));

    var token = new JwtSecurityToken(
      issuer: _twp.ValidIssuer,
      audience: _twp.ValidAudience,
      claims: claims,
      expires: expires,
      signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
  }

  // FIXME: [Important] SecurityStamp is not checked: role changes and revocations do not affect issued tokens until expiry.
  public ClaimsPrincipal? ValidateAccessToken(string token, bool validateLifetime = true)
  {
    var validationParams = _twp.Clone();
    validationParams.ValidateLifetime = validateLifetime;

    ClaimsPrincipal principal;
    SecurityToken validatedToken;
    try
    {
      principal = _tokenHandler.ValidateToken(token, validationParams, out validatedToken);
    }
    catch (Exception ex)
    {
      _logger.LogError("💥Token validation failed: {Message}", ex.Message);
      return null;
    }


    if (validatedToken is not JwtSecurityToken jwtToken ||
      !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
    {
      return null;
    }

    return principal;
  }

  // Only the hash is persisted; the raw token is handed to the client and never stored.
  public (RefreshToken entity, string rawToken) GenerateRefreshToken(string ipAddress, User user)
  {
    var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    var hash = HashToken(rawToken);

    var entity = new RefreshToken
    {
      UserId = user.Id,
      TokenHash = hash,
      CreatedAt = DateTime.UtcNow,
      CreatedByIp = ipAddress,
      ExpiresAt = DateTime.UtcNow.AddDays(_config.GetValue<int>("Security:RTExpiration"))
    };

    return (entity, rawToken);
  }

  // FIXME: [Crit] No concurrency check: parallel requests with the same refresh token both succeed and each get new tokens.
  public async Task<(string token, string refreshToken)> RefreshTokens(User user, RefreshToken oldToken, string ipAddress)
  {
    var newAccessToken = await GenerateAccessToken(user);
    var (newRefreshToken, newRawRefreshToken) = GenerateRefreshToken(ipAddress, user);

    await RevokeRefreshToken(newRefreshToken, oldToken, ipAddress);

    user.RefreshTokens.Add(newRefreshToken);
    _dbContext.Update(user);
    await _dbContext.SaveChangesAsync();

    return (newAccessToken, newRawRefreshToken);
  }

  public async Task RevokeRefreshToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress)
  {
    oldToken.RevokedAt = DateTime.UtcNow;
    oldToken.RevokedByIp = ipAddress;
    oldToken.ReplacedByTokenHash = newToken.TokenHash;
    _dbContext.Update(oldToken);
  }

  public string HashToken(string token)
  {
    return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
  }
}

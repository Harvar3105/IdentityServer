using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Services;

public class TokenService : ITokenService
{
  private const string SecurityStampClaimType = "sstamp";

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
      // Hashed because the raw stamp is the key of Identity's TOTP token providers and the JWT payload is readable.
      new Claim(SecurityStampClaimType, HashToken(await _userManager.GetSecurityStampAsync(user))),
    };

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

  public async Task<ClaimsPrincipal?> ValidateAccessToken(string token, bool validateLifetime = true)
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

    return await IsSecurityStampValid(principal) ? principal : null;
  }

  public async Task<bool> IsSecurityStampValid(ClaimsPrincipal principal)
  {
    var tokenStampHash = principal.FindFirstValue(SecurityStampClaimType);
    if (tokenStampHash == null) return false;

    var user = await _userManager.GetUserAsync(principal);
    if (user?.SecurityStamp == null) return false;

    return HashToken(user.SecurityStamp) == tokenStampHash;
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

  public async Task<RefreshToken?> FindActiveRefreshToken(string rawToken, string ipAddress)
  {
    var tokenHash = HashToken(rawToken);
    var refreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
    if (refreshToken == null) return null;

    if (refreshToken.RevokedAt != null)
    {
      _logger.LogWarning("💥Revoked refresh token reused for user {UserId}; revoking all active refresh tokens", refreshToken.UserId);
      await RevokeAllRefreshTokens(refreshToken.UserId, ipAddress);
      return null;
    }

    return refreshToken.IsActive ? refreshToken : null;
  }

  public async Task RevokeAllRefreshTokens(Guid userId, string ipAddress)
  {
    var revokedAt = DateTime.UtcNow;
    await _dbContext.RefreshTokens
      .Where(rt => rt.UserId == userId && rt.RevokedAt == null)
      .ExecuteUpdateAsync(setters => setters
        .SetProperty(rt => rt.RevokedAt, revokedAt)
        .SetProperty(rt => rt.RevokedByIp, ipAddress));

    var user = await _userManager.FindByIdAsync(userId.ToString());
    if (user != null) await _userManager.UpdateSecurityStampAsync(user);
  }

  public async Task<(string token, string refreshToken)?> RefreshTokens(User user, RefreshToken oldToken, string ipAddress)
  {
    var (newRefreshToken, newRawRefreshToken) = GenerateRefreshToken(ipAddress, user);

    await using var transaction = await _dbContext.Database.BeginTransactionAsync();

    if (!await TryRevokeRefreshToken(newRefreshToken, oldToken, ipAddress)) return null;

    _dbContext.RefreshTokens.Add(newRefreshToken);
    await _dbContext.SaveChangesAsync();
    await transaction.CommitAsync();

    var newAccessToken = await GenerateAccessToken(user);
    return (newAccessToken, newRawRefreshToken);
  }

  public async Task<bool> TryRevokeRefreshToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress)
  {
    // Conditional UPDATE executed in the database: of several concurrent requests holding the same
    // token only one sees RevokedAt == null, the others affect 0 rows and are rejected.
    var revokedAt = DateTime.UtcNow;
    var affectedRows = await _dbContext.RefreshTokens
      .Where(rt => rt.Id == oldToken.Id && rt.RevokedAt == null)
      .ExecuteUpdateAsync(setters => setters
        .SetProperty(rt => rt.RevokedAt, revokedAt)
        .SetProperty(rt => rt.RevokedByIp, ipAddress)
        .SetProperty(rt => rt.ReplacedByTokenHash, newToken.TokenHash));

    return affectedRows == 1;
  }

  public string HashToken(string token)
  {
    return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
  }
}

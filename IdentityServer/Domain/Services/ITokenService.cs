using System.Security.Claims;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface ITokenService
{
  Task<string> GenerateAccessToken(User user);
  (RefreshToken entity, string rawToken) GenerateRefreshToken(string ipAddress, User user);
  ClaimsPrincipal? ValidateAccessToken(string token, bool validateLifetime = true);
  /// <returns>New token pair, or null if <paramref name="oldToken"/> was already revoked by a concurrent request.</returns>
  Task<(string token, string refreshToken)?> RefreshTokens(User user, RefreshToken oldToken, string ipAddress);
  Task<bool> TryRevokeRefreshToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress);
  string HashToken(string token);
}

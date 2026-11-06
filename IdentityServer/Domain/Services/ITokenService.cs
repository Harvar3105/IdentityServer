using System.Security.Claims;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface ITokenService
{
  Task<string> GenerateAccessToken(User user);
  (RefreshToken entity, string rawToken) GenerateRefreshToken(string ipAddress, User user, Guid? sessionId = null);
  Task<ClaimsPrincipal?> ValidateAccessToken(string token, bool validateLifetime = true);
  Task<bool> IsSecurityStampValid(ClaimsPrincipal principal);
  Task<RefreshToken?> FindActiveRefreshToken(string rawToken, string ipAddress);
  Task<bool> RevokeSession(string rawRefreshToken, Guid userId, string ipAddress);
  Task RevokeAllSessions(Guid userId, string ipAddress);
  Task<(string token, string refreshToken)?> RefreshTokens(User user, RefreshToken oldToken, string ipAddress);
  Task<bool> TryRevokeRefreshToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress);
  string HashToken(string token);
}

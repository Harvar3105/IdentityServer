using System.Security.Claims;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface ITokenService
{
  Task<string> GenerateJwtToken(User user);
  (string token, RefreshToken entity) GenerateRefreshToken(string ipAddress, User user);
  ClaimsPrincipal? ValidateToken(string token, bool validateLifetime = true);
  Task<(string token, string refreshToken)> RefreshTokens(User user, RefreshToken oldToken, string ipAddress);
  Task RevokeRTToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress);
  string HashToken(string token);
}

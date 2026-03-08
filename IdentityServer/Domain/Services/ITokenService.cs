using System.Security.Claims;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface ITokenService
{
  Task<string> GenerateAccessToken(User user);
  RefreshToken GenerateRefreshToken(string ipAddress, User user);
  ClaimsPrincipal? ValidateAccessToken(string token, bool validateLifetime = true);
  Task<(string token, string refreshToken)> RefreshTokens(User user, RefreshToken oldToken, string ipAddress);
  Task RevokeRefreshToken(RefreshToken newToken, RefreshToken oldToken, string ipAddress);
  string HashToken(string token);
}

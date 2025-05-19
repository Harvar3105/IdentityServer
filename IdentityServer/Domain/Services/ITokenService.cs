using System.Security.Claims;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface ITokenService
{
    Task<string> GenerateJwtToken(User user);
    RefreshToken GenerateRefreshToken(string ipAddress, User user);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    (bool, dynamic) ValidateToken(string token);
}
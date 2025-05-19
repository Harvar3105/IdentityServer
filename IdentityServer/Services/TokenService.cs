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

    public TokenService(IConfiguration config, TokenValidationParameters twp, UserManager<User> userManager)
    {
        _config = config;
        _twp = twp;
        _userManager = userManager;
    }
    
    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = _twp.Clone();
        validationParameters.ValidateLifetime = false;

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var securityToken);
            if (securityToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
        catch
        {
            return null;
        }
    }

    public async Task<string> GenerateJwtToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName!)
        };

        foreach (var role in await _userManager.GetRolesAsync(user))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = _twp.IssuerSigningKey;
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _twp.ValidIssuer,
            audience: _twp.ValidAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(double.Parse(_config["Security:JWTExpiration"]!)),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public (bool, dynamic) ValidateToken(string token)
    {
        try
        {
            _tokenHandler.ValidateToken(token, _twp, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var claims = jwtToken.Claims.ToDictionary(c => c.Type, c => c.Value);

            return (true, claims);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public RefreshToken GenerateRefreshToken(string ipAddress, User user)
    {
        return new RefreshToken
        {
            UserId = user.Id.ToString(),
            User = user,
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.UtcNow.AddDays(double.Parse(_config["Security:RTExpiration"]!)),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
    }
}

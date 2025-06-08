using System.IdentityModel.Tokens.Jwt;
using System.Text;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly ITokenService _tokenService;
    private readonly ILogger<TokenController> _logger;
    private readonly ApplicationDbContext _dbContext;

    public TokenController(UserManager<User> userManager, ITokenService tokenService, ILogger<TokenController> logger, ApplicationDbContext dbContext)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _logger = logger;
        _dbContext = dbContext;
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] DataModel model)
    {
        _logger.LogInformation("Refreshing token");
        if (string.IsNullOrEmpty(model.JWT) || string.IsNullOrEmpty(model.RefreshToken))
        {
            _logger.LogError("JWT or Refresh Token is missing");
            return BadRequest("JWT or Refresh Token is missing");
        }
            

        var principal = _tokenService.GetPrincipalFromExpiredToken(model.JWT);
        if (principal == null)
        {
            _logger.LogError("Invalid token");
            return BadRequest("Invalid token");
        }

        var username = principal.Identity?.Name;
        var user = await _userManager.Users
            .Include(u => u.RefreshTokens)
            .SingleOrDefaultAsync(u => u.UserName == username);
        if (user == null)
        {
            _logger.LogError("User not found");
            return BadRequest("User not found");
        }

        var refreshToken = user.RefreshTokens.FirstOrDefault(rt =>
            rt.Token == model.RefreshToken && !rt.IsExpired);

        if (refreshToken == null)
        {
            _logger.LogError("Invalid or expired refresh token");
            return BadRequest("Invalid or expired refresh token");
        }

        var newJwt = await _tokenService.GenerateJwtToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);

        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        user.RefreshTokens.Add(newRefreshToken);
        // await _userManager.UpdateAsync(user);
        _dbContext.Update(user);
        await _dbContext.SaveChangesAsync();
        
        return Ok(new
        {
            token = newJwt,
            refreshToken = newRefreshToken.Token
        });
    }
    
    [HttpPost("validate")]
    public IActionResult ValidateToken([FromBody] string token)
    {
        var (success, data) = _tokenService.ValidateToken(token);
        
        return success
            ? Ok(new {valid = true, data})
            : BadRequest(new {valid = false, error = data});
    }

}
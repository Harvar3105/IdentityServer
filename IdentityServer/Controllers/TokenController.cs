using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
  public async Task<IActionResult> RefreshJWTToken([FromBody] DataModel model)
  {
    _logger.LogInformation("⚠️Refreshing token");
    if (string.IsNullOrEmpty(model.RefreshTokenHash))
    {
      _logger.LogError("💥Refresh Token is missing");
      return BadRequest("Refresh Token is missing");
    }

    var now = DateTime.UtcNow;
    var refreshToken = await _dbContext.RefreshTokens
      .FirstOrDefaultAsync(rt => rt.TokenHash.Equals(model.RefreshTokenHash) && rt.RevokedAt == null && rt.ExpiresAt > now);

    if (refreshToken == null)
    {
      _logger.LogError("💥Invalid or expired refresh token");
      return BadRequest("Invalid or expired refresh token");
    }

    var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id.Equals(refreshToken.UserId));
    if (user == null)
    {
      _logger.LogError("💥User not found for refresh token");
      return BadRequest("User not found");
    }

    var result = await _tokenService.RefreshTokens(user, refreshToken, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    return Ok(new ResponseDTO { AccessToken = result.token, RefreshToken = result.refreshToken });
  }

  [HttpPost("validate")]
  public IActionResult ValidateToken([FromBody] string token)
  {
    try
    {
      var principal = _tokenService.ValidateAccessToken(token);
      if (principal == null)
      {
        return BadRequest(new { valid = false, error = "Invalid token" });
      }
      return Ok(new ResponseDTO { IsAaccessTokenValid = true });
    }
    catch (Exception ex)
    {
      return BadRequest(new { valid = false, error = ex.Message });
    }
  }

}

using System.Security.Cryptography;
using System.Text;
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
    if (string.IsNullOrEmpty(model.Jwt) || string.IsNullOrEmpty(model.RefreshToken))
    {
      _logger.LogError("💥JWT or Refresh Token is missing");
      return BadRequest("JWT or Refresh Token is missing");
    }

    var principal = _tokenService.ValidateToken(model.Jwt, false);
    if (principal == null)
    {
      _logger.LogError("💥Invalid token");
      return BadRequest("Invalid token");
    }

    var user = await _userManager.GetUserAsync(principal);
    if (user == null)
    {
      _logger.LogError("💥User not found");
      return BadRequest("User not found");
    }

    var securityStampClaim = principal.FindFirst("security_stamp")?.Value;
    if (securityStampClaim == null || securityStampClaim != user.SecurityStamp)
    {
      return BadRequest("💥Token invalid due to security stamp mismatch");
    }

    var tokenHash = _tokenService.HashToken(model.RefreshToken);
    var refreshTokenHash = user.RefreshTokens.FirstOrDefault(rt =>
        rt.TokenHash.Equals(tokenHash) && rt.IsActive);

    if (refreshTokenHash == null)
    {
      _logger.LogError("💥Invalid or expired refresh token");
      return BadRequest("Invalid or expired refresh token");
    }

    var result = await _tokenService.RefreshTokens(user, refreshTokenHash, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    return Ok(new
    {
      token = result.token,
      refreshToken = result.refreshToken
    });
  }

  [HttpPost("validate")]
  public IActionResult ValidateToken([FromBody] string token)
  {
    try
    {
      var principal = _tokenService.ValidateToken(token);
      if (principal == null)
      {
        return BadRequest(new { valid = false, error = "Invalid token" });
      }
      return Ok(new { valid = true });
    } catch (Exception ex)
    {
      return BadRequest(new { valid = false, error = ex.Message });
    }
  }

}

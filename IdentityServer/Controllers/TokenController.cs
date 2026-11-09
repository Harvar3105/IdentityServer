using IdentityServer.Controllers.Contracts;
using IdentityServer.Domain.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
  // Same text as /api/auth/session uses for a rejected token.
  private const string RejectedTokenMessage = "Invalid or expired token";

  private readonly ITokenService _tokenService;
  private readonly ILogger<TokenController> _logger;
  private readonly ApplicationDbContext _dbContext;

  public TokenController(ITokenService tokenService, ILogger<TokenController> logger, ApplicationDbContext dbContext)
  {
    _tokenService = tokenService;
    _logger = logger;
    _dbContext = dbContext;
  }

  // Every rejection gets the same 401 and message as /api/auth/session, so the caller cannot tell the reasons apart;
  // the actual reason is only logged.
  [HttpPost("refresh")]
  [ProducesResponseType<TokenPairResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
  {
    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var refreshToken = await _tokenService.FindActiveRefreshToken(request.RefreshToken, ipAddress);

    if (refreshToken == null)
    {
      _logger.LogError("💥Invalid or expired refresh token");
      return Unauthorized(RejectedTokenMessage);
    }

    var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id.Equals(refreshToken.UserId));
    if (user == null)
    {
      _logger.LogError("💥User not found for refresh token");
      return Unauthorized(RejectedTokenMessage);
    }

    var result = await _tokenService.RefreshTokens(user, refreshToken, ipAddress);
    if (result == null)
    {
      _logger.LogError("💥Refresh token was already used by a concurrent request");
      return Unauthorized(RejectedTokenMessage);
    }

    return Ok(new TokenPairResponse { AccessToken = result.Value.token, RefreshToken = result.Value.refreshToken });
  }

  // Always 200: an invalid token is a normal answer of this endpoint, not a malformed request.
  [HttpPost("validate")]
  [ProducesResponseType<ValidateTokenResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> Validate([FromBody] ValidateTokenRequest request)
  {
    var principal = await _tokenService.ValidateAccessToken(request.AccessToken);
    return Ok(new ValidateTokenResponse { Valid = principal != null });
  }
}

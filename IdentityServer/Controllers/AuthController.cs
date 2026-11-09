using IdentityServer.Controllers.Contracts;
using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using IdentityServer.Middleware;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
[EnableRateLimiting(RateLimitPolicies.CredentialEndpoints)]
public class AuthController : ControllerBase
{
  private readonly UserManager<User> _userManager;
  private readonly SignInManager<User> _signInManager;
  private readonly ITokenService _tokenService;
  private readonly ApplicationDbContext _dbContext;
  private readonly RoleSettings _roleSettings;
  private readonly ILogger<AuthController> _logger;

  public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, ITokenService tokenService, ApplicationDbContext context, IOptions<RoleSettings> roleSettings, ILogger<AuthController> logger)
  {
    _userManager = userManager;
    _signInManager = signInManager;
    _tokenService = tokenService;
    _dbContext = context;
    _roleSettings = roleSettings.Value;
    _logger = logger;
  }

  [HttpPost("register")]
  [ProducesResponseType<AuthResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> Register([FromBody] RegisterRequest request)
  {
    var user = new User
    {
      UserName = request.Username,
      CreatedAt = DateTime.UtcNow,
      LastLogin = DateTime.UtcNow,
      Email = request.Email,
    };

    // FIXME: A registration that loses a race on the unique username/email index gets DbUpdateException (500)
    // instead of a DuplicateUserName/DuplicateEmail error.
    var result = await _userManager.CreateAsync(user, request.Password);
    if (!result.Succeeded) return BadRequest(result.Errors);

    var (refreshToken, rawRefreshToken) = _tokenService.GenerateRefreshToken(GetIpAddress(), user);
    user.RefreshTokens.Add(refreshToken);

    await _userManager.AddToRoleAsync(user, _roleSettings.Initial);

    await _userManager.UpdateAsync(user);
    await _dbContext.SaveChangesAsync();

    var accessToken = await _tokenService.GenerateAccessToken(user);
    return Ok(new AuthResponse
    {
      User = new UserDTO(user),
      Roles = [_roleSettings.Initial],
      AccessToken = accessToken,
      RefreshToken = rawRefreshToken
    });
  }

  [HttpPost("login")]
  [ProducesResponseType<AuthResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> Login([FromBody] LoginRequest request)
  {
    var user = string.IsNullOrEmpty(request.Username)
      ? await _userManager.FindByEmailAsync(request.Email!)
      : await _userManager.FindByNameAsync(request.Username);
    if (user == null) return Unauthorized("Invalid credentials");

    var result = await _signInManager.PasswordSignInAsync(user, request.Password, isPersistent: false, lockoutOnFailure: true);
    if (result.IsLockedOut)
      return StatusCode(StatusCodes.Status429TooManyRequests, "Too many failed attempts. Try again later.");
    if (!result.Succeeded)
      return Unauthorized("Invalid credentials");

    var userRoles = await _userManager.GetRolesAsync(user);

    var accessToken = await _tokenService.GenerateAccessToken(user);
    var (refreshToken, rawRefreshToken) = _tokenService.GenerateRefreshToken(GetIpAddress(), user);
    _dbContext.RefreshTokens.Add(refreshToken);
    user.LastLogin = DateTime.UtcNow;
    await _dbContext.SaveChangesAsync();

    return Ok(new AuthResponse
    {
      User = new UserDTO(user),
      Roles = userRoles,
      AccessToken = accessToken,
      RefreshToken = rawRefreshToken
    });
  }

  // Restores a client session from stored tokens: returns the user and roles, plus a rotated token pair
  // when only the refresh token is still valid.
  [HttpPost("session")]
  [ProducesResponseType<SessionResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> Session([FromBody] SessionRequest request)
  {
    var principal = string.IsNullOrEmpty(request.AccessToken)
      ? null
      : await _tokenService.ValidateAccessToken(request.AccessToken);
    if (principal != null)
    {
      var user = await _userManager.GetUserAsync(principal);
      if (user == null) return Unauthorized("Invalid or expired token");

      return Ok(new SessionResponse { User = new UserDTO(user), Roles = await _userManager.GetRolesAsync(user) });
    }

    if (string.IsNullOrEmpty(request.RefreshToken)) return Unauthorized("Invalid or expired token");

    var ipAddress = GetIpAddress();
    var storedRefreshToken = await _tokenService.FindActiveRefreshToken(request.RefreshToken, ipAddress);
    if (storedRefreshToken == null) return Unauthorized("Invalid or expired token");

    var tokenOwner = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id.Equals(storedRefreshToken.UserId));
    if (tokenOwner == null) return Unauthorized("Invalid or expired token");

    var newTokens = await _tokenService.RefreshTokens(tokenOwner, storedRefreshToken, ipAddress);
    if (newTokens == null) return Unauthorized("Invalid or expired token");

    return Ok(new SessionResponse
    {
      User = new UserDTO(tokenOwner),
      Roles = await _userManager.GetRolesAsync(tokenOwner),
      AccessToken = newTokens.Value.token,
      RefreshToken = newTokens.Value.refreshToken
    });
  }

  // Always 204: the response does not reveal whether the token existed, belonged to the caller or was already revoked.
  [HttpPost("logout")]
  [Authorize]
  public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
  {
    if (!TryGetCurrentUserId(out var userId)) return Unauthorized();

    if (!await _tokenService.RevokeSession(request.RefreshToken, userId, GetIpAddress()))
      _logger.LogWarning("⚠️Logout of user {UserId} revoked nothing: token unknown, foreign or already revoked", userId);

    return NoContent();
  }

  [HttpPost("logoutAll")]
  [Authorize]
  public async Task<IActionResult> LogoutAll()
  {
    if (!TryGetCurrentUserId(out var userId)) return Unauthorized();

    if (!await _tokenService.RevokeAllSessions(userId, GetIpAddress()))
      _logger.LogWarning("⚠️Logout from all sessions of user {UserId} revoked no refresh tokens: no active sessions", userId);

    return NoContent();
  }

  private bool TryGetCurrentUserId(out Guid userId) => Guid.TryParse(_userManager.GetUserId(User), out userId);

  private string GetIpAddress() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

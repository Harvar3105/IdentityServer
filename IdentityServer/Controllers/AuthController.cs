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
  public async Task<IActionResult> Register([FromBody] DataModel model)
  {
    if (model.Email == null || model.Password == null)
    {
      return BadRequest($"Invalid data, {model}");
    }

    var user = new User
    {
      UserName = model.Username,
      CreatedAt = DateTime.UtcNow,
      LastLogin = DateTime.UtcNow,
      Email = model.Email,
    };

    var result = await _userManager.CreateAsync(user, model.Password);
    if (!result.Succeeded) return BadRequest(result.Errors);

    var (refreshToken, rawRefreshToken) = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);
    user.RefreshTokens.Add(refreshToken);

    await _userManager.AddToRoleAsync(user, _roleSettings.Initial);

    await _userManager.UpdateAsync(user);
    await _dbContext.SaveChangesAsync();

    var accessToken = await _tokenService.GenerateAccessToken(user);
    return Ok(new ResponseDTO{User = new UserDTO(user), AccessToken = accessToken, RefreshToken = rawRefreshToken});
  }

  [HttpPost("login")]
  public async Task<IActionResult> Login([FromBody] DataModel model)
  {
    if (model.Username != null)
    {
      return await LoginByUsername(model);
    }
    else if (model.Email != null)
    {
      return await LoginByEmail(model);
    }
    else if (model.AccessToken != null || model.RefreshTokenHash != null)
    {
      return await LoginWithTokens(model);
    }

    return BadRequest("Could not find suitable auth method!");
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

  private async Task<IActionResult> LoginWithTokens(DataModel model)
  {
    var principal = string.IsNullOrEmpty(model.AccessToken)
      ? null
      : await _tokenService.ValidateAccessToken(model.AccessToken);
    if (principal == null)
    {
      if (string.IsNullOrEmpty(model.RefreshTokenHash)) return Unauthorized("Invalid or expired token");

      var login = await TryLoginWithRefreshToken(model.RefreshTokenHash);
      if (login == null) return Unauthorized("Invalid or expired token");

      return Ok(new
      {
        User = new UserDTO(login.Value.User),
        Roles = login.Value.Roles,
        AccessToken = login.Value.NewJwt,
        RefreshToken = login.Value.NewRt
      });
    }

    var user = await _userManager.GetUserAsync(principal);
    if (user == null) return Unauthorized("Invalid or expired token");

    var roles = await _userManager.GetRolesAsync(user);
    return Ok(new ResponseDTO{User = new UserDTO(user), UserRoles = roles});
  }

  private async Task<(User User, IList<string> Roles, string NewJwt, string NewRt)?> TryLoginWithRefreshToken(string refreshToken)
  {
    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var rtEntity = await _tokenService.FindActiveRefreshToken(refreshToken, ipAddress);
    if (rtEntity == null) return null;
    var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id.Equals(rtEntity.UserId));
    if (user == null) return null;

    var newTokens = await _tokenService.RefreshTokens(user, rtEntity, ipAddress);
    if (newTokens == null) return null;

    var roles = await _userManager.GetRolesAsync(user);

    return (User: user, Roles: roles, NewJwt: newTokens.Value.token, NewRt: newTokens.Value.refreshToken);
  }

  private async Task<IActionResult> LoginByEmail(DataModel model)
  {
    if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
      return BadRequest("Email or Password is missing");

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
      return Unauthorized("Invalid credentials");

    return await TryLogin(user, model.Password);
  }

  private async Task<IActionResult> LoginByUsername(DataModel model)
  {
    if (string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
      return BadRequest("Username or Password is missing");

    var user = await _userManager.FindByNameAsync(model.Username);
    if (user == null)
      return Unauthorized("Invalid credentials");

    return await TryLogin(user, model.Password);
  }

  private async Task<IActionResult> TryLogin(User user, string password)
  {
    var result = await _signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: true);
    if (result.IsLockedOut)
      return StatusCode(StatusCodes.Status429TooManyRequests, "Too many failed attempts. Try again later.");
    if (!result.Succeeded)
      return Unauthorized("Invalid credentials");

    var userRoles = await _userManager.GetRolesAsync(user);

    var accessToken = await _tokenService.GenerateAccessToken(user);
    var (refreshToken, rawRefreshToken) = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);
    _dbContext.RefreshTokens.Add(refreshToken);
    user.LastLogin = DateTime.UtcNow;
    await _dbContext.SaveChangesAsync();

    return Ok(new ResponseDTO{User = new UserDTO(user), UserRoles = userRoles, AccessToken = accessToken, RefreshToken = rawRefreshToken});
  }

}

// TODO: Split the shared DataModel into dedicated request contracts per endpoint (register, login, refresh)
// in Controllers/Contracts, so that each endpoint accepts only its own fields. Changes the public JSON contract.
public class DataModel
{
  public Guid? Id { get; set; }
  public string? Username { get; set; }
  public string? Password { get; set; }
  public string? Email { get; set; }
  public ICollection<string>? Roles { get; set; }

  public string? AccessToken { get; set; }
  // TODO: Rename to RefreshToken: clients now send the raw token, not its hash. Changes the public JSON contract.
  public string? RefreshTokenHash { get; set; }

  public override string ToString()
  {
    return $"{Username}\n{Email}\n{RefreshTokenHash}\n{AccessToken}";
  }
}

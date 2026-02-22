using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using IdentityServer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
  private readonly UserManager<User> _userManager;
  private readonly SignInManager<User> _signInManager;
  private readonly ITokenService _tokenService;
  private readonly ApplicationDbContext _dbContext;

  public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, ITokenService tokenService, ApplicationDbContext context)
  {
    _userManager = userManager;
    _signInManager = signInManager;
    _tokenService = tokenService;
    _dbContext = context;
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

    var refreshToken = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);
    user.RefreshTokens.Add(refreshToken.entity);
    await _userManager.AddToRoleAsync(user, "User");

    if (model.Roles != null && model.Roles.Any())
    {
      foreach (var role in model.Roles)
      {
        await _userManager.AddToRoleAsync(user, role);
      }
    }

    await _userManager.UpdateAsync(user);
    await _dbContext.SaveChangesAsync();

    var jwt = await _tokenService.GenerateJwtToken(user);
    return Ok(new ResponseDTO{User = new UserDTO(user), AccessToken = jwt, RefreshToken = refreshToken.token});
  }

  [HttpPost("login")]
  public async Task<IActionResult> Login([FromBody] DataModel model)
  {
    try
    {
      if (model.Username != null)
      {
        return await LoginByUsername(model);
      }
      else if (model.Email != null)
      {
        return await LoginByEmail(model);
      }
      else if (model.Jwt != null)
      {
        return await LoginWithJWT(model);
      }

      return BadRequest("Could not find suitable auth method!");
    }
    catch (Exception ex)
    {
      return BadRequest(new { Fail = "❌Could not login!", Reason = ex.Message });
    }
  }

  private async Task<IActionResult> LoginWithJWT(DataModel model)
  {
    try
    {
      var principal = _tokenService.ValidateToken(model.Jwt!);
      if (principal == null)
      {
        var login = await TryLoginWithRefreshToken(model.RefreshToken!);
        if (login != null) return Ok(new
        {
          User = login.Value.User,
          Roles = login.Value.Roles,
          jwt = login.Value.NewJwt,
          rt = login.Value.NewRt
        });
        throw new Exception("Invalid JWT!");
      }

      var user = await _userManager.GetUserAsync(principal);
      if (user == null)
      {
        throw new Exception("User not found!");
      }

      var roles = await _userManager.GetRolesAsync(user);
      return Ok(new ResponseDTO{User = new UserDTO(user), UserRoles = roles});
    }
    catch (Exception ex)
    {
      return Unauthorized(ex.Message);
    }
  }

  private async Task<(User User, IList<string> Roles, string NewJwt, string NewRt)?> TryLoginWithRefreshToken(string refreshToken)
  {
    var rthash = _tokenService.HashToken(refreshToken);
    var user = await _userManager.Users
      .Where(u => u.RefreshTokens.Any(rt =>
        rt.TokenHash.Equals(rthash) &&
        rt.IsActive))
      .FirstOrDefaultAsync();
    if (user == null) return null;

    var newTokens = await _tokenService.RefreshTokens
    (
      user,
      user.RefreshTokens.First(rt => rt.TokenHash.Equals(rthash) && rt.IsActive),
      HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"
    );

    var roles = await _userManager.GetRolesAsync(user);

    return (User: user, Roles: roles, NewJwt: newTokens.token, NewRt: newTokens.refreshToken);
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
    //TODO: Add lockout?
    var result = await _signInManager.PasswordSignInAsync(user, password, false, false);
    if (!result.Succeeded)
      return Unauthorized("Invalid credentials");

    var userRoles = await _userManager.GetRolesAsync(user);

    var rt = _dbContext.RefreshTokens
      .Where(ut => ut.UserId.Equals(user.Id))
      .OrderByDescending(ut => ut.CreatedAt)
      .FirstOrDefault();

    if (rt == null)
    {
      var jwt = await _tokenService.GenerateJwtToken(user);
      var refreshToken = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);
      user.RefreshTokens.Add(refreshToken.entity);
      await _userManager.UpdateAsync(user);

      return Ok(new ResponseDTO{User = new UserDTO(user), UserRoles = userRoles, AccessToken = jwt, RefreshToken = refreshToken.token});
    }

    var tokens = await _tokenService.RefreshTokens(user, rt, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
    return Ok(new ResponseDTO{User = new UserDTO(user), UserRoles = userRoles, AccessToken = tokens.token, RefreshToken = tokens.refreshToken});
  }

}

public class DataModel
{
  public Guid? Id { get; set; }
  public string? Username { get; set; }
  public string? Password { get; set; }
  public string? Email { get; set; }
  public ICollection<string>? Roles { get; set; }

  public string? Jwt { get; set; }
  public string? RefreshToken { get; set; }

  public override string ToString()
  {
    return $"{Username}\n{Password}\n{Email}\n{RefreshToken}\n{Jwt}";
  }
}

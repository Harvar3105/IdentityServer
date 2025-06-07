using System.IdentityModel.Tokens.Jwt;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
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
    private readonly ApplicationDbContext _context;

    public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, ITokenService tokenService, ApplicationDbContext context)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _context = context;
    }

    // POST: api/auth/register
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] DataModel model)
    {
        if (model.FirstName == null || model.LastName == null || model.Password == null)
        {
            return BadRequest($"Invalid data, {model}");
        }

        var user = new User
        {
            UserName = model.Username,
            FirstName = model.FirstName,
            LastName = model.LastName,
            CreatedAt = DateTime.UtcNow,
            Email = model.Email,
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);
        
        var jwt = _tokenService.GenerateJwtToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);
        
        user.RefreshTokens.Add(refreshToken);
        await _userManager.UpdateAsync(user);
        await _userManager.AddToRoleAsync(user, "User");
        
        await _context.SaveChangesAsync();

        return Ok(new
        {
            token = jwt,
            refreshToken = refreshToken.Token
        });
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] DataModel model)
    {
        if (model == null)
        {
            return BadRequest("No credentials recieved!");
        }

        if (model.Username != null)
        {
            return await LoginByUsername(model);
        } else if (model.Email != null)
        {
            return await LoginByEmail(model);
        }
        else if (model.JWT != null)
        {
            return await LoginWithJWT(model);
        }

        return BadRequest("Could not find suitable auth method!");
    }

    private async Task<IActionResult> LoginWithJWT(DataModel model)
    {
        try
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(model.JWT);
            if (principal == null)
            {
                throw new Exception("Invalid JWT!");
            }

            var username = principal.Claims.FirstOrDefault(c => c.Type.Equals(JwtRegisteredClaimNames.UniqueName))?.Value;
            if (string.IsNullOrEmpty(username))
            {
                throw new Exception("Invalid identity!");
            }
            
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                throw new Exception("User not found!");
            }
            
            var roles = await _userManager.GetRolesAsync(user);
            return Ok(new DataModel
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Username = user.UserName,
                Email = user.Email,
                Roles = roles.ToList(),
                JWT = model.JWT,
                RefreshToken = null
            });
        }
        catch (Exception ex)
        {
            if (!string.IsNullOrEmpty(model.RefreshToken))
            {
                var result = await TryLoginWithRefreshToken(model.RefreshToken);
                if (result != null) return Ok(result);
            }
            
            return Unauthorized(ex.Message);
        }
    }
    
    private async Task<DataModel?> TryLoginWithRefreshToken(string refreshToken)
    {
        var user = await _userManager.Users
            .Where(u => u.RefreshTokens.Any(rt =>
                rt.Token == refreshToken &&
                rt.Expires > DateTime.UtcNow &&
                rt.Revoked == null))
            .FirstOrDefaultAsync();

        if (user == null) return null;

        var newJwt = await _tokenService.GenerateJwtToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken(
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);

        user.RefreshTokens.Add(newRefreshToken);
        await _userManager.UpdateAsync(user);

        var roles = await _userManager.GetRolesAsync(user);

        return new DataModel
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Username = user.UserName,
            Email = user.Email,
            Roles = roles.ToList(),
            JWT = newJwt,
            RefreshToken = newRefreshToken.Token
        };
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
        var result = await _signInManager.PasswordSignInAsync(user, password, false, false);
        if (!result.Succeeded)
            return Unauthorized("Invalid credentials");

        var jwt = await _tokenService.GenerateJwtToken(user);

        var refreshToken = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", user);

        user.RefreshTokens.Add(refreshToken);
        await _userManager.UpdateAsync(user);

        var userRoles = await _userManager.GetRolesAsync(user);
        var data = new DataModel
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Username = user.UserName,
            Email = user.Email,
            Roles = userRoles.ToList(),
            JWT = jwt,
            RefreshToken = refreshToken.Token
        };
        return Ok(data);
    }

}

public class DataModel
{
    public Guid? Id { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Email { get; set; }
    public ICollection<string>? Roles { get; set; }
    
    public string? JWT { get; set; }
    public string? RefreshToken { get; set; }

    public override string ToString()
    {
        return $"{Username}\n{FirstName}\n{LastName}\n{Password}\n{Email}\n{RefreshToken}\n{JWT}";
    }
}
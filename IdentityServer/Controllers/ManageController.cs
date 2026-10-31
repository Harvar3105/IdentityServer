using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class ManageController : ControllerBase
{
  private readonly UserManager<User> _userManager;
  private readonly RoleSettings _roleSettings;

  public ManageController(UserManager<User> userManager, IOptions<RoleSettings> roleSettings)
  {
    _userManager = userManager;
    _roleSettings = roleSettings.Value;
  }

  [HttpPost("assignRole")]
  public async Task<IActionResult> AssignRole([FromBody] UserRoleRequest request)
  {
    if (!_roleSettings.IsAvailable(request.Role)) return BadRequest($"Role {request.Role} does not exist!");
    if (!CanManageRole(request.Role)) return Forbid();

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return BadRequest("User not found!");

    var success = await _userManager.AddToRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot assign {request.Role} to user!");

    await _userManager.UpdateSecurityStampAsync(user);

    return Ok("Assigned");
  }

  [HttpPost("removeRole")]
  public async Task<IActionResult> RemoveRole([FromBody] UserRoleRequest request)
  {
    if (!CanManageRole(request.Role)) return Forbid();

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return BadRequest("User not found!");

    if (_roleSettings.IsRoot(request.Role) && (await _userManager.GetUsersInRoleAsync(_roleSettings.Root)).Count <= 1)
      return BadRequest("Cannot remove the root role from its last holder!");

    var success = await _userManager.RemoveFromRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot remove {request.Role} from user!");

    await _userManager.UpdateSecurityStampAsync(user);

    return Ok("Removed");
  }

  [HttpGet("userRoles")]
  public async Task<IActionResult> GetUserRoles([FromQuery] Guid userId)
  {
    if (!IsRoleManagerOrSelf(userId)) return Forbid();

    var user = await _userManager.FindByIdAsync(userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok(await _userManager.GetRolesAsync(user));
  }

  [HttpGet("hasRole")]
  public async Task<IActionResult> CheckUserRole([FromQuery] Guid userId, [FromQuery] string role)
  {
    if (!IsRoleManagerOrSelf(userId)) return Forbid();

    var user = await _userManager.FindByIdAsync(userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok(await _userManager.IsInRoleAsync(user, role));
  }

  // Root can manage every role; managers can manage only roles that are neither root nor manager roles.
  private bool CanManageRole(string role)
  {
    if (User.IsInRole(_roleSettings.Root)) return true;
    return !_roleSettings.IsPrivileged(role) && IsRoleManager();
  }

  private bool IsRoleManager()
  {
    return User.IsInRole(_roleSettings.Root) || _roleSettings.Managers.Any(User.IsInRole);
  }

  private bool IsRoleManagerOrSelf(Guid userId)
  {
    return IsRoleManager() || _userManager.GetUserId(User) == userId.ToString();
  }
}

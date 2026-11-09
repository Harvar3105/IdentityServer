using IdentityServer.Controllers.Contracts;
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
  [ProducesResponseType<UserRolesResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> AssignRole([FromBody] UserRoleRequest request)
  {
    if (!_roleSettings.IsAvailable(request.Role)) return BadRequest($"Role {request.Role} does not exist!");
    if (!CanManageRole(request.Role)) return Forbid();

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return NotFound("User not found!");

    var success = await _userManager.AddToRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot assign {request.Role} to user!");

    await _userManager.UpdateSecurityStampAsync(user);

    return Ok(await CreateUserRolesResponse(user));
  }

  [HttpPost("removeRole")]
  [ProducesResponseType<UserRolesResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> RemoveRole([FromBody] UserRoleRequest request)
  {
    if (!CanManageRole(request.Role)) return Forbid();

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return NotFound("User not found!");

    if (_roleSettings.IsRoot(request.Role) && (await _userManager.GetUsersInRoleAsync(_roleSettings.Root)).Count <= 1)
      return BadRequest("Cannot remove the root role from its last holder!");

    var success = await _userManager.RemoveFromRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot remove {request.Role} from user!");

    await _userManager.UpdateSecurityStampAsync(user);

    return Ok(await CreateUserRolesResponse(user));
  }

  [HttpGet("userRoles")]
  [ProducesResponseType<UserRolesResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> GetUserRoles([FromQuery] UserRolesQuery query)
  {
    if (!IsRoleManagerOrSelf(query.UserId)) return Forbid();

    var user = await _userManager.FindByIdAsync(query.UserId.ToString());
    if (user is null) return NotFound("User not found!");

    return Ok(await CreateUserRolesResponse(user));
  }

  [HttpGet("hasRole")]
  [ProducesResponseType<HasRoleResponse>(StatusCodes.Status200OK)]
  public async Task<IActionResult> CheckUserRole([FromQuery] HasRoleQuery query)
  {
    if (!IsRoleManagerOrSelf(query.UserId)) return Forbid();

    var user = await _userManager.FindByIdAsync(query.UserId.ToString());
    if (user is null) return NotFound("User not found!");

    return Ok(new HasRoleResponse { HasRole = await _userManager.IsInRoleAsync(user, query.Role) });
  }

  private async Task<UserRolesResponse> CreateUserRolesResponse(User user) =>
    new() { UserId = user.Id, Roles = await _userManager.GetRolesAsync(user) };

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

using IdentityServer.Domain.Dtos;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
public class ManageController : ControllerBase
{
  private readonly UserManager<User> _userManager;

  public ManageController(UserManager<User> userManager)
  {
    _userManager = userManager;
  }

  [Authorize(Roles = "ADMIN")]
  [HttpPost("assign-role")]
  public async Task<IActionResult> AssignRole([FromBody] UserRoleRequest request)
  {
    if (request.Role.Equals("ADMIN")) return BadRequest("Assigning highest overall role is forbidden!");

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return BadRequest("User not found!");

    var success = await _userManager.AddToRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot assign {request.Role} to user!");

    return Ok("Assigned");
  }

  [Authorize(Roles = "ADMIN")]
  [HttpPost("remove-role")]
  public async Task<IActionResult> RemoveRole([FromBody] UserRoleRequest request)
  {
    if (request.Role.Equals("ADMIN")) return BadRequest("Cannot remove highest role!");

    var user = await _userManager.FindByIdAsync(request.UserId.ToString());
    if (user is null) return BadRequest("User not found!");

    var success = await _userManager.RemoveFromRoleAsync(user, request.Role);
    if (!success.Succeeded) return BadRequest($"Cannot remove {request.Role} from user!");

    return Ok("Removed");
  }

  [Authorize]
  [HttpGet("user-roles")]
  public async Task<IActionResult> GetUserRoles([FromQuery] Guid userId)
  {
    if (!IsAdminOrSelf(userId)) return Forbid();

    var user = await _userManager.FindByIdAsync(userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok(await _userManager.GetRolesAsync(user));
  }

  [Authorize]
  [HttpGet("has-role")]
  public async Task<IActionResult> CheckUserRole([FromQuery] Guid userId, [FromQuery] string role)
  {
    if (!IsAdminOrSelf(userId)) return Forbid();

    var user = await _userManager.FindByIdAsync(userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok((await _userManager.GetRolesAsync(user)).Any(r => r.Equals(role)));
  }

  private bool IsAdminOrSelf(Guid userId)
  {
    return User.IsInRole("ADMIN") || _userManager.GetUserId(User) == userId.ToString();
  }
}
using Duende.IdentityServer.Extensions;
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
  public async Task<IActionResult> AsignRole([FromBody] DataModel data)
  {
    if (data.role.IsNullOrEmpty()) return BadRequest("Role must be specified!");
    if (data.role.Equals("ADMIN")) return BadRequest("Assigning highest overall role is forbidden!");

    var user = await _userManager.FindByIdAsync(data.userId.ToString());
    if (user is null) return BadRequest("User not found!");

    var success = await _userManager.AddToRoleAsync(user, data.role);
    if (!success.Succeeded) return BadRequest($"Cannot assign {data.role} to user!");

    return Ok("Assigned");
  }

  [Authorize(Roles = "ADMIN")]
  public async Task<IActionResult> RemoveRole([FromBody] DataModel data)
  {
    if (data.role.IsNullOrEmpty()) return BadRequest("Role must be specified!");
    if (data.role.Equals("ADMIN")) return BadRequest("Cannot remove highest role!");

    var user = await _userManager.FindByIdAsync(data.userId.ToString());
    if (user is null) return BadRequest("User not found!");

    var success = await _userManager.RemoveFromRoleAsync(user, data.role);
    if (!success.Succeeded) return BadRequest($"Cannot remove {data.role} from user!");

    return Ok("Removed");
  }

  public async Task<IActionResult> GetUserRoles([FromBody] DataModel data)
  {
    var user = await _userManager.FindByIdAsync(data.userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok(await _userManager.GetRolesAsync(user));
  }

  public async Task<IActionResult> CheckUserRole([FromBody] DataModel data)
  {
    if (data.role.IsNullOrEmpty()) return BadRequest("Role must be specified!");

    var user = await _userManager.FindByIdAsync(data.userId.ToString());
    if (user is null) return BadRequest("User not found!");

    return Ok((await _userManager.GetRolesAsync(user)).Any(r => r.Equals(data.role)));
  }

  public class DataModel
  {
    public required Guid userId { get; set; }
    public required string? role { get; set; }
  }
}
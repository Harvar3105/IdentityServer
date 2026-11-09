using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

public class UserRoleRequest
{
  public required Guid UserId { get; init; }
  [Required] public string Role { get; init; } = string.Empty;
}

namespace IdentityServer.Domain.Dtos;

public class UserRoleRequest
{
  public required Guid UserId { get; set; }
  public required string Role { get; set; }
}

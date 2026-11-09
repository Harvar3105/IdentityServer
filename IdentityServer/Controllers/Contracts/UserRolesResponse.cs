namespace IdentityServer.Controllers.Contracts;

// Returned by userRoles and, with the roles after the change, by assignRole and removeRole.
public class UserRolesResponse
{
  public required Guid UserId { get; init; }
  public required IEnumerable<string> Roles { get; init; }
}

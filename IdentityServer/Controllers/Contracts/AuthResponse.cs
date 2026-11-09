using IdentityServer.Domain.Dtos;

namespace IdentityServer.Controllers.Contracts;

// Returned by register and password login: the user, their roles and the tokens of a new session.
public class AuthResponse
{
  public required UserDTO User { get; init; }
  public required IEnumerable<string> Roles { get; init; }
  public required string AccessToken { get; init; }
  public required string RefreshToken { get; init; }
}

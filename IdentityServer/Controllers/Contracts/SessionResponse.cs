using IdentityServer.Domain.Dtos;

namespace IdentityServer.Controllers.Contracts;

// Tokens are set only when the session was restored by the refresh token: it has been rotated,
// so the client must replace both of its tokens. With a valid access token they are null.
public class SessionResponse
{
  public required UserDTO User { get; init; }
  public required IEnumerable<string> Roles { get; init; }
  public string? AccessToken { get; init; }
  public string? RefreshToken { get; init; }
}

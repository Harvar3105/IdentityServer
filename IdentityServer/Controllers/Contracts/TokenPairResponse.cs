namespace IdentityServer.Controllers.Contracts;

// The presented refresh token is revoked by rotation, so the client must replace both tokens.
public class TokenPairResponse
{
  public required string AccessToken { get; init; }
  public required string RefreshToken { get; init; }
}

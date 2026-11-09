using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

// The access token is checked first; the refresh token is used (and rotated) only when the access token
// is missing or no longer valid.
public class SessionRequest : IValidatableObject
{
  public string? AccessToken { get; init; }
  public string? RefreshToken { get; init; }

  public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
  {
    if (string.IsNullOrEmpty(AccessToken) && string.IsNullOrEmpty(RefreshToken))
      yield return new ValidationResult("Specify accessToken, refreshToken or both.", [nameof(AccessToken), nameof(RefreshToken)]);
  }
}

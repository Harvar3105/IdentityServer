using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

// The user is identified by exactly one of Username or Email.
public class LoginRequest : IValidatableObject
{
  public string? Username { get; init; }
  public string? Email { get; init; }
  [Required] public string Password { get; init; } = string.Empty;

  public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
  {
    var hasUsername = !string.IsNullOrEmpty(Username);
    var hasEmail = !string.IsNullOrEmpty(Email);
    if (hasUsername == hasEmail)
      yield return new ValidationResult("Specify either username or email.", [nameof(Username), nameof(Email)]);
  }
}

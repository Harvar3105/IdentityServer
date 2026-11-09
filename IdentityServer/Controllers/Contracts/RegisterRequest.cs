using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

public class RegisterRequest
{
  [Required] public string Username { get; init; } = string.Empty;
  [Required, EmailAddress] public string Email { get; init; } = string.Empty;
  [Required] public string Password { get; init; } = string.Empty;
}

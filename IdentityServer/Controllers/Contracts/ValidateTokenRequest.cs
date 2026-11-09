using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

public class ValidateTokenRequest
{
  [Required] public string AccessToken { get; init; } = string.Empty;
}

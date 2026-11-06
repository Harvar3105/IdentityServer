using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

public class LogoutRequest
{
  [Required] public string RefreshToken { get; init; } = string.Empty;
}

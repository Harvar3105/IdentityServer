using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

public class RefreshRequest
{
  [Required] public string RefreshToken { get; init; } = string.Empty;
}

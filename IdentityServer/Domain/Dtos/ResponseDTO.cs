using IdentityServer.Entities;

namespace IdentityServer.Domain.Dtos;

public class ResponseDTO
{
  public UserDTO? User { get; set; }
  public IEnumerable<string>? UserRoles { get; set; }
  public string? AccessToken { get; set; }
  public string? RefreshToken { get; set; }
  public bool? IsAaccessTokenValid { get; set; }
}
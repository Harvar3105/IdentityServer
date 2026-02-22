using IdentityServer.Entities;

namespace IdentityServer.Domain.Dtos;

public class UserDTO
{
  public Guid Id { get; set; }
  public DateTime CreatedAt { get; set; }
  public DateTime? LastLogin { get; set; }

  public string? Username { get; set; } = null!;
  public string? Email { get; set; } = null!;

  public UserDTO(User user)
  {
    Id = user.Id;
    CreatedAt = user.CreatedAt;
    LastLogin = user.LastLogin;
    Username = user.UserName;
    Email = user.Email;
  }
}
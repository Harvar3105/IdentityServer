using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Entities;

public class User : IdentityUser<Guid>
{
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime? LastLogin { get; set; }
  // FIXME: This navigation is not mapped to the Identity UserId foreign key, so EF creates a shadow UserId1 column
  // in AspNetUserClaims and the collection never contains the claims stored by UserManager.
  public List<UserClaim> Claims { get; set; } = new List<UserClaim>();
  public List<RefreshToken> RefreshTokens { get; set; } = new();
  public ProfilePicture? ProfilePicture { get; set; }
}

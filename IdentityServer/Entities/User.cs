using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Entities;

public class User : IdentityUser<Guid>
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLogin { get; set; }

    public List<UserClaim> Claims { get; set; } = new List<UserClaim>();
    public List<RefreshToken> RefreshTokens { get; set; } = new();
}
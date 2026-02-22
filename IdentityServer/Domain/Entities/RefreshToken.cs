using System.Text.Json.Serialization;

namespace IdentityServer.Entities;

public class RefreshToken
{
  public Guid Id { get; set; }
  public string TokenHash { get; set; } = null!;
  public DateTime ExpiresAt { get; set; }
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public string? CreatedByIp { get; set; }
  public DateTime? RevokedAt { get; set; }
  public string? RevokedByIp { get; set; }
  public string? ReplacedByTokenHash { get; set; }
  public Guid UserId { get; set; }
  [JsonIgnore]
  public User User { get; set; } = null!;
  public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
  public bool IsActive => RevokedAt == null && !IsExpired;
}

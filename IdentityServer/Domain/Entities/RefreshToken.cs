using System.Text.Json.Serialization;

namespace IdentityServer.Entities;

public class RefreshToken
{
  public Guid Id { get; set; }
  // FIXME: TokenHash is nvarchar(max) without an index, so every refresh-token lookup scans the whole table.
  // Needs a bounded length (a Base64 SHA-256 hash is 44 chars) and a unique index; requires a migration.
  public string TokenHash { get; set; } = null!;
  public DateTime ExpiresAt { get; set; }
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public string? CreatedByIp { get; set; }
  public DateTime? RevokedAt { get; set; }
  public string? RevokedByIp { get; set; }
  public string? ReplacedByTokenHash { get; set; }
  // Shared by every token rotated from one sign-in (password login or registration), i.e. identifies one session.
  // TODO: Use FamilyId in reuse detection so that reuse of a rotated token revokes only the compromised session
  // instead of every session of the user (see TokenService.FindActiveRefreshToken).
  public Guid FamilyId { get; set; }
  public Guid UserId { get; set; }
  [JsonIgnore]
  public User User { get; set; } = null!;
  public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
  public bool IsActive => RevokedAt == null && !IsExpired;
}

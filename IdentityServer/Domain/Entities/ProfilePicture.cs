using System.Text.Json.Serialization;

namespace IdentityServer.Entities;

// TODO: Decide separately whether a picture can be set by an external URL; that option brings SSRF, tracking
// and content-swap risks and needs its own design.
public class ProfilePicture
{
  public Guid UserId { get; set; }
  public byte[] Content { get; set; } = null!;
  public string ContentType { get; set; } = null!;
  public long SizeBytes { get; set; }
  public int Width { get; set; }
  public int Height { get; set; }
  public string ContentHash { get; set; } = null!;

  public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

  [JsonIgnore]
  public User User { get; set; } = null!;
}

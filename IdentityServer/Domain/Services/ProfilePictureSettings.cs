namespace IdentityServer.Domain.Services;

public class ProfilePictureSettings
{
  // Formats whose signature and dimensions the server can read; configuration may only narrow this list.
  public static readonly IReadOnlyList<string> SupportedContentTypes = ImageContentTypes.All;

  public long MaxSizeBytes { get; set; }
  public int MinWidth { get; set; }
  public int MinHeight { get; set; }
  public int MaxWidth { get; set; }
  public int MaxHeight { get; set; }
  public List<string> AllowedContentTypes { get; set; } = [];

  public bool IsAllowed(string contentType) =>
    AllowedContentTypes.Contains(contentType, StringComparer.OrdinalIgnoreCase);
}

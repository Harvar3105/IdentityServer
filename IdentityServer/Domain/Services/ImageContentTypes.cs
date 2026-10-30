namespace IdentityServer.Domain.Services;

public static class ImageContentTypes
{
  public const string Jpeg = "image/jpeg";
  public const string Png = "image/png";
  public const string Webp = "image/webp";

  public static readonly IReadOnlyList<string> All = [Jpeg, Png, Webp];
}

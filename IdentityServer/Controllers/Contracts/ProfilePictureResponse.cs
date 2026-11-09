using IdentityServer.Domain.Dtos;

namespace IdentityServer.Controllers.Contracts;

// ContentHash is the ETag value (without quotes) that GET /api/profilePicture/{userId} returns.
public class ProfilePictureResponse
{
  public required string ContentType { get; init; }
  public required int Width { get; init; }
  public required int Height { get; init; }
  public required long SizeBytes { get; init; }
  public required string ContentHash { get; init; }
  public required DateTime UpdatedAt { get; init; }

  public static ProfilePictureResponse From(ProfilePictureMetadata metadata) => new()
  {
    ContentType = metadata.Image.ContentType,
    Width = metadata.Image.Width,
    Height = metadata.Image.Height,
    SizeBytes = metadata.SizeBytes,
    ContentHash = metadata.ContentHash,
    UpdatedAt = DateTime.SpecifyKind(metadata.UpdatedAt, DateTimeKind.Utc)
  };
}

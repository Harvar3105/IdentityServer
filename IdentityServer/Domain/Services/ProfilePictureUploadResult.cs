using IdentityServer.Domain.Dtos;

namespace IdentityServer.Domain.Services;

public enum ProfilePictureUploadError
{
  Empty,
  TooLarge,
  UnknownFormat,
  FormatNotAllowed,
  DimensionsOutOfRange,
  UserNotFound
}

public record ProfilePictureUploadResult(ProfilePictureMetadata? Picture, ProfilePictureUploadError? Error)
{
  public bool Succeeded => Error is null;

  public static ProfilePictureUploadResult Success(ProfilePictureMetadata picture) => new(picture, null);
  public static ProfilePictureUploadResult Failure(ProfilePictureUploadError error) => new(null, error);
}

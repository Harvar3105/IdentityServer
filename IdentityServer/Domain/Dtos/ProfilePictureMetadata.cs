namespace IdentityServer.Domain.Dtos;

public record ProfilePictureMetadata(
  ImageInfo Image,
  long SizeBytes,
  string ContentHash,
  DateTime UpdatedAt);

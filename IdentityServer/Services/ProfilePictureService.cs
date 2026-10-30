using System.Security.Cryptography;
using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Repositories;
using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityServer.Services;

public class ProfilePictureService : IProfilePictureService
{
  private const int ReadBufferSize = 81920;

  private readonly IProfilePictureRepository _repository;
  private readonly UserManager<User> _userManager;
  private readonly ProfilePictureSettings _settings;

  public ProfilePictureService(IProfilePictureRepository repository, UserManager<User> userManager,
    IOptions<ProfilePictureSettings> settings)
  {
    _repository = repository;
    _userManager = userManager;
    _settings = settings.Value;
  }

  public async Task<ProfilePictureUploadResult> Upload(Guid userId, Stream content,
    CancellationToken cancellationToken = default)
  {
    var bytes = await ReadWithLimit(content, _settings.MaxSizeBytes, cancellationToken);
    if (bytes is null)
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.TooLarge);
    if (bytes.Length == 0)
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.Empty);

    var image = ImageInspector.Inspect(bytes);
    if (image is null)
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.UnknownFormat);
    if (!_settings.IsAllowed(image.ContentType))
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.FormatNotAllowed);
    if (image.Width < _settings.MinWidth || image.Width > _settings.MaxWidth ||
        image.Height < _settings.MinHeight || image.Height > _settings.MaxHeight)
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.DimensionsOutOfRange);

    // Access tokens stay valid after the user is deleted, so the token subject alone does not prove the user exists.
    if (!await _userManager.Users.AnyAsync(u => u.Id == userId, cancellationToken))
      return ProfilePictureUploadResult.Failure(ProfilePictureUploadError.UserNotFound);

    // TODO: Re-encode the image on the server (e.g. with SkiaSharp) to drop EXIF metadata such as GPS location,
    // discard data appended after the image and normalize the stored size; only the header is validated now.
    var picture = new ProfilePicture
    {
      UserId = userId,
      Content = bytes,
      ContentType = image.ContentType,
      SizeBytes = bytes.Length,
      Width = image.Width,
      Height = image.Height,
      ContentHash = Convert.ToHexStringLower(SHA256.HashData(bytes)),
      UpdatedAt = DateTime.UtcNow
    };
    await _repository.Save(picture, cancellationToken);

    return ProfilePictureUploadResult.Success(
      new ProfilePictureMetadata(image, picture.SizeBytes, picture.ContentHash, picture.UpdatedAt));
  }

  public Task<ProfilePicture?> Get(Guid userId, CancellationToken cancellationToken = default) =>
    _repository.Get(userId, cancellationToken);

  public Task<ProfilePictureMetadata?> GetMetadata(Guid userId, CancellationToken cancellationToken = default) =>
    _repository.GetMetadata(userId, cancellationToken);

  public Task<bool> Delete(Guid userId, CancellationToken cancellationToken = default) =>
    _repository.Delete(userId, cancellationToken);

  private static async Task<byte[]?> ReadWithLimit(Stream content, long maxBytes, CancellationToken cancellationToken)
  {
    using var buffer = new MemoryStream();
    var chunk = new byte[ReadBufferSize];
    int read;
    while ((read = await content.ReadAsync(chunk, cancellationToken)) > 0)
    {
      if (buffer.Length + read > maxBytes)
        return null;
      buffer.Write(chunk, 0, read);
    }

    return buffer.ToArray();
  }
}

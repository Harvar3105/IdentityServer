using IdentityServer.Domain.Dtos;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Services;

public interface IProfilePictureService
{
  Task<ProfilePictureUploadResult> Upload(Guid userId, Stream content, CancellationToken cancellationToken = default);
  Task<ProfilePicture?> Get(Guid userId, CancellationToken cancellationToken = default);
  Task<ProfilePictureMetadata?> GetMetadata(Guid userId, CancellationToken cancellationToken = default);
  Task<bool> Delete(Guid userId, CancellationToken cancellationToken = default);
}

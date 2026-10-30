using IdentityServer.Domain.Dtos;
using IdentityServer.Entities;

namespace IdentityServer.Domain.Repositories;

public interface IProfilePictureRepository
{
  Task<ProfilePicture?> Get(Guid userId, CancellationToken cancellationToken = default);
  Task<ProfilePictureMetadata?> GetMetadata(Guid userId, CancellationToken cancellationToken = default);
  Task Save(ProfilePicture picture, CancellationToken cancellationToken = default);
  Task<bool> Delete(Guid userId, CancellationToken cancellationToken = default);
}

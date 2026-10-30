using IdentityServer.Domain.Dtos;
using IdentityServer.Domain.Repositories;
using IdentityServer.Entities;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Repositories;

public class ProfilePictureRepository : IProfilePictureRepository
{
  private const int SqlUniqueConstraintViolation = 2627;
  private const int SqlUniqueIndexViolation = 2601;

  private readonly ApplicationDbContext _dbContext;

  public ProfilePictureRepository(ApplicationDbContext dbContext)
  {
    _dbContext = dbContext;
  }

  public Task<ProfilePicture?> Get(Guid userId, CancellationToken cancellationToken = default) =>
    _dbContext.ProfilePictures
      .AsNoTracking()
      .FirstOrDefaultAsync(p => p.UserId == userId, cancellationToken);

  public Task<ProfilePictureMetadata?> GetMetadata(Guid userId, CancellationToken cancellationToken = default) =>
    _dbContext.ProfilePictures
      .Where(p => p.UserId == userId)
      .Select(p => new ProfilePictureMetadata(
        new ImageInfo(p.ContentType, p.Width, p.Height), p.SizeBytes, p.ContentHash, p.UpdatedAt))
      .FirstOrDefaultAsync(cancellationToken);

  public async Task Save(ProfilePicture picture, CancellationToken cancellationToken = default)
  {
    if (await UpdateExisting(picture, cancellationToken) > 0) return;

    _dbContext.ProfilePictures.Add(picture);
    try
    {
      await _dbContext.SaveChangesAsync(cancellationToken);
    }
    catch (DbUpdateException ex) when (ex.InnerException is SqlException
      { Number: SqlUniqueConstraintViolation or SqlUniqueIndexViolation })
    {
      _dbContext.Entry(picture).State = EntityState.Detached;
      await UpdateExisting(picture, cancellationToken);
    }
  }

  public async Task<bool> Delete(Guid userId, CancellationToken cancellationToken = default) =>
    await _dbContext.ProfilePictures
      .Where(p => p.UserId == userId)
      .ExecuteDeleteAsync(cancellationToken) > 0;

  private Task<int> UpdateExisting(ProfilePicture picture, CancellationToken cancellationToken) =>
    _dbContext.ProfilePictures
      .Where(p => p.UserId == picture.UserId)
      .ExecuteUpdateAsync(setters => setters
        .SetProperty(p => p.Content, picture.Content)
        .SetProperty(p => p.ContentType, picture.ContentType)
        .SetProperty(p => p.SizeBytes, picture.SizeBytes)
        .SetProperty(p => p.Width, picture.Width)
        .SetProperty(p => p.Height, picture.Height)
        .SetProperty(p => p.ContentHash, picture.ContentHash)
        .SetProperty(p => p.UpdatedAt, picture.UpdatedAt), cancellationToken);
}

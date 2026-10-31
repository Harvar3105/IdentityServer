using IdentityServer.Entities;

namespace IdentityServer.Tests.Unit.Entities;

public class RefreshTokenTests
{
  [Fact]
  public void NotRevokedAndNotExpired_IsActive()
  {
    var token = new RefreshToken { ExpiresAt = DateTime.UtcNow.AddMinutes(1) };

    Assert.False(token.IsExpired);
    Assert.True(token.IsActive);
  }

  [Fact]
  public void PastExpiry_IsExpiredAndInactive()
  {
    var token = new RefreshToken { ExpiresAt = DateTime.UtcNow.AddSeconds(-1) };

    Assert.True(token.IsExpired);
    Assert.False(token.IsActive);
  }

  [Fact]
  public void Revoked_IsInactiveBeforeExpiry()
  {
    var token = new RefreshToken { ExpiresAt = DateTime.UtcNow.AddDays(1), RevokedAt = DateTime.UtcNow };

    Assert.False(token.IsExpired);
    Assert.False(token.IsActive);
  }
}

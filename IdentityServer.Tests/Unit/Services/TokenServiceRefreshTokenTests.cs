using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Tests.Unit.Services;

public class TokenServiceRefreshTokenTests : IAsyncLifetime
{
  private const string AttackerIp = "10.0.0.66";
  private const string RotationIp = "10.0.0.20";

  private TokenServiceFixture _fixture = null!;

  public Task InitializeAsync()
  {
    _fixture = TokenServiceFixture.Create();
    return Task.CompletedTask;
  }

  public async Task DisposeAsync() => await _fixture.DisposeAsync();

  [Fact]
  public void HashToken_ReturnsBase64Sha256()
  {
    Assert.Equal("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", _fixture.TokenService.HashToken("abc"));
  }

  [Fact]
  public void HashToken_IsDeterministicAndDistinguishesInputs()
  {
    Assert.Equal(_fixture.TokenService.HashToken("token"), _fixture.TokenService.HashToken("token"));
    Assert.NotEqual(_fixture.TokenService.HashToken("token"), _fixture.TokenService.HashToken("Token"));
  }

  [Fact]
  public async Task GenerateRefreshToken_PersistsOnlyHashOfRawToken()
  {
    var user = await _fixture.CreateUserAsync();

    var (entity, rawToken) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);

    Assert.Equal(64, Convert.FromBase64String(rawToken).Length);
    Assert.NotEqual(rawToken, entity.TokenHash);
    Assert.Equal(_fixture.TokenService.HashToken(rawToken), entity.TokenHash);
  }

  [Fact]
  public async Task GenerateRefreshToken_FillsOwnerIpAndLifetime()
  {
    var user = await _fixture.CreateUserAsync();
    var createdAfter = DateTime.UtcNow;

    var (entity, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);

    Assert.Equal(user.Id, entity.UserId);
    Assert.Equal(TokenServiceFixture.IpAddress, entity.CreatedByIp);
    Assert.InRange(entity.CreatedAt, createdAfter, DateTime.UtcNow);
    Assert.Equal(TokenServiceFixture.RefreshTokenExpirationDays, (entity.ExpiresAt - entity.CreatedAt).TotalDays, precision: 3);
    Assert.Null(entity.RevokedAt);
    Assert.True(entity.IsActive);
  }

  [Fact]
  public async Task GenerateRefreshToken_ProducesUniqueTokens()
  {
    var user = await _fixture.CreateUserAsync();

    var rawTokens = Enumerable.Range(0, 20)
      .Select(_ => _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user).rawToken)
      .ToList();

    Assert.Equal(rawTokens.Count, rawTokens.Distinct().Count());
  }

  [Fact]
  public async Task FindActiveRefreshToken_ActiveToken_ReturnsEntity()
  {
    var user = await _fixture.CreateUserAsync();
    var (entity, rawToken) = await _fixture.AddRefreshTokenAsync(user);

    var found = await _fixture.TokenService.FindActiveRefreshToken(rawToken, TokenServiceFixture.IpAddress);

    Assert.NotNull(found);
    Assert.Equal(entity.Id, found.Id);
  }

  [Fact]
  public async Task FindActiveRefreshToken_UnknownToken_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    await _fixture.AddRefreshTokenAsync(user);

    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken("unknown-token", TokenServiceFixture.IpAddress));
  }

  [Fact]
  public async Task FindActiveRefreshToken_HashInsteadOfRawToken_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var (entity, _) = await _fixture.AddRefreshTokenAsync(user);

    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken(entity.TokenHash, TokenServiceFixture.IpAddress));
  }

  [Fact]
  public async Task FindActiveRefreshToken_ExpiredToken_ReturnsNullWithoutRevokingOtherTokens()
  {
    var user = await _fixture.CreateUserAsync();
    var (expired, expiredRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var (other, _) = await _fixture.AddRefreshTokenAsync(user);
    expired.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
    await _fixture.DbContext.SaveChangesAsync();
    var stampBefore = await _fixture.UserManager.GetSecurityStampAsync(user);

    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken(expiredRawToken, TokenServiceFixture.IpAddress));

    Assert.Null((await _fixture.ReloadRefreshTokenAsync(other.Id)).RevokedAt);
    Assert.Equal(stampBefore, await _fixture.UserManager.GetSecurityStampAsync(user));
  }

  [Fact]
  public async Task FindActiveRefreshToken_RevokedTokenReuse_RevokesAllUserTokensAndSecurityStamp()
  {
    var user = await _fixture.CreateUserAsync();
    var (stolen, stolenRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var rotated = await _fixture.TokenService.RefreshTokens(user, stolen, TokenServiceFixture.IpAddress);
    Assert.NotNull(rotated);
    var (otherSession, _) = await _fixture.AddRefreshTokenAsync(user);
    var stampBefore = await _fixture.GetPersistedSecurityStampAsync(user.Id);
    _fixture.StartNewRequest();

    var found = await _fixture.TokenService.FindActiveRefreshToken(stolenRawToken, AttackerIp);

    Assert.Null(found);
    var activeTokens = await _fixture.DbContext.RefreshTokens.AsNoTracking()
      .Where(rt => rt.UserId == user.Id && rt.RevokedAt == null)
      .CountAsync();
    Assert.Equal(0, activeTokens);
    Assert.Equal(AttackerIp, (await _fixture.ReloadRefreshTokenAsync(otherSession.Id)).RevokedByIp);
    _fixture.StartNewRequest();
    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken(rotated.Value.refreshToken, TokenServiceFixture.IpAddress));
    Assert.NotEqual(stampBefore, await _fixture.GetPersistedSecurityStampAsync(user.Id));
  }

  [Fact]
  public async Task FindActiveRefreshToken_RevokedTokenReuse_InvalidatesIssuedAccessTokens()
  {
    var user = await _fixture.CreateUserAsync();
    var (stolen, stolenRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var rotated = await _fixture.TokenService.RefreshTokens(user, stolen, TokenServiceFixture.IpAddress);
    Assert.NotNull(rotated);
    Assert.NotNull(await _fixture.TokenService.ValidateAccessToken(rotated.Value.token));
    _fixture.StartNewRequest();

    await _fixture.TokenService.FindActiveRefreshToken(stolenRawToken, AttackerIp);
    _fixture.StartNewRequest();

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(rotated.Value.token));
  }

  [Fact]
  public async Task RevokeAllRefreshTokens_RevokesOnlyActiveTokensOfThatUser()
  {
    var user = await _fixture.CreateUserAsync("alice");
    var otherUser = await _fixture.CreateUserAsync("bob");
    var (active, _) = await _fixture.AddRefreshTokenAsync(user);
    var (alreadyRevoked, _) = await _fixture.AddRefreshTokenAsync(user);
    var (otherUserToken, _) = await _fixture.AddRefreshTokenAsync(otherUser);
    var earlierRevocation = DateTime.UtcNow.AddDays(-1);
    alreadyRevoked.RevokedAt = earlierRevocation;
    alreadyRevoked.RevokedByIp = "192.168.0.1";
    await _fixture.DbContext.SaveChangesAsync();

    await _fixture.TokenService.RevokeAllRefreshTokens(user.Id, AttackerIp);

    var reloadedActive = await _fixture.ReloadRefreshTokenAsync(active.Id);
    Assert.NotNull(reloadedActive.RevokedAt);
    Assert.Equal(AttackerIp, reloadedActive.RevokedByIp);

    var reloadedAlreadyRevoked = await _fixture.ReloadRefreshTokenAsync(alreadyRevoked.Id);
    Assert.Equal(earlierRevocation, reloadedAlreadyRevoked.RevokedAt);
    Assert.Equal("192.168.0.1", reloadedAlreadyRevoked.RevokedByIp);

    Assert.Null((await _fixture.ReloadRefreshTokenAsync(otherUserToken.Id)).RevokedAt);
  }

  [Fact]
  public async Task RevokeAllRefreshTokens_UpdatesSecurityStampOnlyOfThatUser()
  {
    var user = await _fixture.CreateUserAsync("alice");
    var otherUser = await _fixture.CreateUserAsync("bob");
    var userStampBefore = await _fixture.UserManager.GetSecurityStampAsync(user);
    var otherUserStampBefore = await _fixture.UserManager.GetSecurityStampAsync(otherUser);

    await _fixture.TokenService.RevokeAllRefreshTokens(user.Id, TokenServiceFixture.IpAddress);

    Assert.NotEqual(userStampBefore, await _fixture.UserManager.GetSecurityStampAsync(user));
    Assert.Equal(otherUserStampBefore, await _fixture.UserManager.GetSecurityStampAsync(otherUser));
  }

  [Fact]
  public async Task RevokeAllRefreshTokens_UnknownUser_DoesNotThrow()
  {
    await _fixture.TokenService.RevokeAllRefreshTokens(Guid.NewGuid(), TokenServiceFixture.IpAddress);
  }

  [Fact]
  public async Task RefreshTokens_RotatesRefreshTokenAndIssuesValidAccessToken()
  {
    var user = await _fixture.CreateUserAsync();
    var (oldToken, oldRawToken) = await _fixture.AddRefreshTokenAsync(user);

    var result = await _fixture.TokenService.RefreshTokens(user, oldToken, RotationIp);

    Assert.NotNull(result);
    var (accessToken, newRawToken) = result.Value;
    Assert.NotEqual(oldRawToken, newRawToken);
    Assert.NotNull(await _fixture.TokenService.ValidateAccessToken(accessToken));

    var newToken = await _fixture.TokenService.FindActiveRefreshToken(newRawToken, TokenServiceFixture.IpAddress);
    Assert.NotNull(newToken);
    Assert.Equal(user.Id, newToken.UserId);
    Assert.Equal(RotationIp, newToken.CreatedByIp);

    var reloadedOld = await _fixture.ReloadRefreshTokenAsync(oldToken.Id);
    Assert.NotNull(reloadedOld.RevokedAt);
    Assert.Equal(RotationIp, reloadedOld.RevokedByIp);
    Assert.Equal(newToken.TokenHash, reloadedOld.ReplacedByTokenHash);
  }

  [Fact]
  public async Task RefreshTokens_SameOldTokenTwice_SecondCallReturnsNullAndStoresNothing()
  {
    var user = await _fixture.CreateUserAsync();
    var (oldToken, _) = await _fixture.AddRefreshTokenAsync(user);

    var first = await _fixture.TokenService.RefreshTokens(user, oldToken, TokenServiceFixture.IpAddress);
    var tokenCountAfterFirst = await _fixture.DbContext.RefreshTokens.CountAsync();
    var second = await _fixture.TokenService.RefreshTokens(user, oldToken, TokenServiceFixture.IpAddress);

    Assert.NotNull(first);
    Assert.Null(second);
    Assert.Equal(tokenCountAfterFirst, await _fixture.DbContext.RefreshTokens.CountAsync());
    Assert.Equal(
      _fixture.TokenService.HashToken(first.Value.refreshToken),
      (await _fixture.ReloadRefreshTokenAsync(oldToken.Id)).ReplacedByTokenHash);
  }

  [Fact]
  public async Task TryRevokeRefreshToken_SucceedsOnlyOnce()
  {
    var user = await _fixture.CreateUserAsync();
    var (oldToken, _) = await _fixture.AddRefreshTokenAsync(user);
    var (firstReplacement, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);
    var (secondReplacement, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);

    Assert.True(await _fixture.TokenService.TryRevokeRefreshToken(firstReplacement, oldToken, TokenServiceFixture.IpAddress));
    Assert.False(await _fixture.TokenService.TryRevokeRefreshToken(secondReplacement, oldToken, AttackerIp));

    var reloadedOld = await _fixture.ReloadRefreshTokenAsync(oldToken.Id);
    Assert.Equal(firstReplacement.TokenHash, reloadedOld.ReplacedByTokenHash);
    Assert.Equal(TokenServiceFixture.IpAddress, reloadedOld.RevokedByIp);
  }

  [Fact]
  public async Task TryRevokeRefreshToken_UnknownToken_ReturnsFalse()
  {
    var user = await _fixture.CreateUserAsync();
    var (notPersisted, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);
    var (replacement, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);

    Assert.False(await _fixture.TokenService.TryRevokeRefreshToken(replacement, notPersisted, TokenServiceFixture.IpAddress));
  }
}

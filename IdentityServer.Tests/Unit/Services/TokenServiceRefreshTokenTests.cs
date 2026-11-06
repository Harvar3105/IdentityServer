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
  public async Task GenerateRefreshToken_WithoutSessionId_StartsNewSession()
  {
    var user = await _fixture.CreateUserAsync();

    var (first, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);
    var (second, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user);

    Assert.NotEqual(Guid.Empty, first.SessionId);
    Assert.NotEqual(first.SessionId, second.SessionId);
  }

  [Fact]
  public async Task GenerateRefreshToken_WithSessionId_JoinsThatSession()
  {
    var user = await _fixture.CreateUserAsync();
    var sessionId = Guid.NewGuid();

    var (entity, _) = _fixture.TokenService.GenerateRefreshToken(TokenServiceFixture.IpAddress, user, sessionId);

    Assert.Equal(sessionId, entity.SessionId);
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
  public async Task FindActiveRefreshToken_TokenOfRevokedSession_ReturnsNullWithoutRevokingOtherSessions()
  {
    var user = await _fixture.CreateUserAsync();
    var (_, loggedOutRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var (otherSession, _) = await _fixture.AddRefreshTokenAsync(user);
    Assert.True(await _fixture.TokenService.RevokeSession(loggedOutRawToken, user.Id, TokenServiceFixture.IpAddress));
    var stampBefore = await _fixture.GetPersistedSecurityStampAsync(user.Id);
    _fixture.StartNewRequest();

    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken(loggedOutRawToken, TokenServiceFixture.IpAddress));

    Assert.Null((await _fixture.ReloadRefreshTokenAsync(otherSession.Id)).RevokedAt);
    Assert.Equal(stampBefore, await _fixture.GetPersistedSecurityStampAsync(user.Id));
  }

  [Fact]
  public async Task RevokeSession_ActiveToken_RevokesOnlyThatSessionAndKeepsSecurityStamp()
  {
    var user = await _fixture.CreateUserAsync();
    var (loggedOut, loggedOutRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var (otherSession, _) = await _fixture.AddRefreshTokenAsync(user);
    var stampBefore = await _fixture.GetPersistedSecurityStampAsync(user.Id);

    Assert.True(await _fixture.TokenService.RevokeSession(loggedOutRawToken, user.Id, AttackerIp));

    var reloadedLoggedOut = await _fixture.ReloadRefreshTokenAsync(loggedOut.Id);
    Assert.NotNull(reloadedLoggedOut.RevokedAt);
    Assert.Equal(AttackerIp, reloadedLoggedOut.RevokedByIp);
    Assert.Null(reloadedLoggedOut.ReplacedByTokenHash);
    Assert.Null((await _fixture.ReloadRefreshTokenAsync(otherSession.Id)).RevokedAt);
    Assert.Equal(stampBefore, await _fixture.GetPersistedSecurityStampAsync(user.Id));
  }

  [Fact]
  public async Task RevokeSession_RotatedToken_RevokesActiveSuccessor()
  {
    var user = await _fixture.CreateUserAsync();
    var (rotatedToken, rotatedRawToken) = await _fixture.AddRefreshTokenAsync(user);
    var rotation = await _fixture.TokenService.RefreshTokens(user, rotatedToken, RotationIp);
    Assert.NotNull(rotation);
    _fixture.StartNewRequest();

    Assert.True(await _fixture.TokenService.RevokeSession(rotatedRawToken, user.Id, TokenServiceFixture.IpAddress));

    _fixture.StartNewRequest();
    Assert.Null(await _fixture.TokenService.FindActiveRefreshToken(rotation.Value.refreshToken, TokenServiceFixture.IpAddress));
  }

  [Fact]
  public async Task RevokeSession_AlreadyRevokedSession_ReturnsFalseAndKeepsFirstRevocation()
  {
    var user = await _fixture.CreateUserAsync();
    var (loggedOut, loggedOutRawToken) = await _fixture.AddRefreshTokenAsync(user);
    Assert.True(await _fixture.TokenService.RevokeSession(loggedOutRawToken, user.Id, TokenServiceFixture.IpAddress));
    var firstRevocation = (await _fixture.ReloadRefreshTokenAsync(loggedOut.Id)).RevokedAt;

    Assert.False(await _fixture.TokenService.RevokeSession(loggedOutRawToken, user.Id, AttackerIp));

    var reloaded = await _fixture.ReloadRefreshTokenAsync(loggedOut.Id);
    Assert.Equal(firstRevocation, reloaded.RevokedAt);
    Assert.Equal(TokenServiceFixture.IpAddress, reloaded.RevokedByIp);
  }

  [Fact]
  public async Task RevokeSession_TokenOfAnotherUser_ReturnsFalseAndKeepsItActive()
  {
    var user = await _fixture.CreateUserAsync("alice");
    var otherUser = await _fixture.CreateUserAsync("bob");
    var (otherUserToken, otherUserRawToken) = await _fixture.AddRefreshTokenAsync(otherUser);
    await _fixture.AddRefreshTokenAsync(user);

    Assert.False(await _fixture.TokenService.RevokeSession(otherUserRawToken, user.Id, AttackerIp));

    Assert.Null((await _fixture.ReloadRefreshTokenAsync(otherUserToken.Id)).RevokedAt);
    Assert.Equal(0, await _fixture.DbContext.RefreshTokens.AsNoTracking().CountAsync(rt => rt.RevokedAt != null));
  }

  [Fact]
  public async Task RevokeSession_UnknownToken_ReturnsFalse()
  {
    var user = await _fixture.CreateUserAsync();
    await _fixture.AddRefreshTokenAsync(user);

    Assert.False(await _fixture.TokenService.RevokeSession("unknown-token", user.Id, TokenServiceFixture.IpAddress));

    Assert.Equal(0, await _fixture.DbContext.RefreshTokens.AsNoTracking().CountAsync(rt => rt.RevokedAt != null));
  }

  [Fact]
  public async Task RevokeAllSessions_RevokesOnlyActiveTokensOfThatUser()
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

    Assert.True(await _fixture.TokenService.RevokeAllSessions(user.Id, AttackerIp));

    var reloadedActive = await _fixture.ReloadRefreshTokenAsync(active.Id);
    Assert.NotNull(reloadedActive.RevokedAt);
    Assert.Equal(AttackerIp, reloadedActive.RevokedByIp);

    var reloadedAlreadyRevoked = await _fixture.ReloadRefreshTokenAsync(alreadyRevoked.Id);
    Assert.Equal(earlierRevocation, reloadedAlreadyRevoked.RevokedAt);
    Assert.Equal("192.168.0.1", reloadedAlreadyRevoked.RevokedByIp);

    Assert.Null((await _fixture.ReloadRefreshTokenAsync(otherUserToken.Id)).RevokedAt);
  }

  [Fact]
  public async Task RevokeAllSessions_UpdatesSecurityStampOnlyOfThatUser()
  {
    var user = await _fixture.CreateUserAsync("alice");
    var otherUser = await _fixture.CreateUserAsync("bob");
    var userStampBefore = await _fixture.UserManager.GetSecurityStampAsync(user);
    var otherUserStampBefore = await _fixture.UserManager.GetSecurityStampAsync(otherUser);

    await _fixture.TokenService.RevokeAllSessions(user.Id, TokenServiceFixture.IpAddress);

    Assert.NotEqual(userStampBefore, await _fixture.UserManager.GetSecurityStampAsync(user));
    Assert.Equal(otherUserStampBefore, await _fixture.UserManager.GetSecurityStampAsync(otherUser));
  }

  [Fact]
  public async Task RevokeAllSessions_NoActiveSessions_ReturnsFalseAndStillUpdatesSecurityStamp()
  {
    var user = await _fixture.CreateUserAsync();
    var (_, loggedOutRawToken) = await _fixture.AddRefreshTokenAsync(user);
    Assert.True(await _fixture.TokenService.RevokeSession(loggedOutRawToken, user.Id, TokenServiceFixture.IpAddress));
    var stampBefore = await _fixture.GetPersistedSecurityStampAsync(user.Id);

    Assert.False(await _fixture.TokenService.RevokeAllSessions(user.Id, TokenServiceFixture.IpAddress));

    Assert.NotEqual(stampBefore, await _fixture.GetPersistedSecurityStampAsync(user.Id));
  }

  [Fact]
  public async Task RevokeAllSessions_UnknownUser_ReturnsFalse()
  {
    Assert.False(await _fixture.TokenService.RevokeAllSessions(Guid.NewGuid(), TokenServiceFixture.IpAddress));
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
    Assert.Equal(oldToken.SessionId, newToken.SessionId);

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

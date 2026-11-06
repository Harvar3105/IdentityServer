using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Tests.Unit.Services;

public class TokenServiceAccessTokenTests : IAsyncLifetime
{
  private TokenServiceFixture _fixture = null!;

  public Task InitializeAsync()
  {
    _fixture = TokenServiceFixture.Create();
    return Task.CompletedTask;
  }

  public async Task DisposeAsync() => await _fixture.DisposeAsync();

  [Fact]
  public async Task GenerateAccessToken_ContainsUserClaimsAndRoles()
  {
    var user = await _fixture.CreateUserAsync("alice", "user", "manager");

    var token = await _fixture.TokenService.GenerateAccessToken(user);

    var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
    Assert.Equal(user.Id.ToString(), jwt.Subject);
    Assert.Equal("alice", jwt.Claims.Single(c => c.Type == ClaimTypes.Name).Value);
    Assert.Equal(
      new[] { "manager", "user" },
      jwt.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).Order());
    Assert.False(string.IsNullOrEmpty(jwt.Id));
  }

  [Fact]
  public async Task GenerateAccessToken_UsesConfiguredIssuerAudienceAlgorithmAndLifetime()
  {
    var user = await _fixture.CreateUserAsync();
    var issuedAfter = DateTime.UtcNow;

    var token = await _fixture.TokenService.GenerateAccessToken(user);

    var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
    Assert.Equal(TokenServiceFixture.Issuer, jwt.Issuer);
    Assert.Equal(new[] { TokenServiceFixture.Audience }, jwt.Audiences);
    Assert.Equal(SecurityAlgorithms.HmacSha256, jwt.Header.Alg);

    var expectedExpiry = issuedAfter.AddMinutes(TokenServiceFixture.AccessTokenExpirationMinutes);
    Assert.InRange(jwt.ValidTo, expectedExpiry.AddSeconds(-5), expectedExpiry.AddSeconds(5));
  }

  [Fact]
  public async Task GenerateAccessToken_StoresHashedSecurityStamp()
  {
    var user = await _fixture.CreateUserAsync();
    var rawStamp = await _fixture.UserManager.GetSecurityStampAsync(user);

    var token = await _fixture.TokenService.GenerateAccessToken(user);

    var stampClaim = new JwtSecurityTokenHandler().ReadJwtToken(token).Claims.Single(c => c.Type == "sstamp").Value;
    Assert.NotEqual(rawStamp, stampClaim);
    Assert.Equal(_fixture.TokenService.HashToken(rawStamp), stampClaim);
  }

  [Fact]
  public async Task GenerateAccessToken_IssuesUniqueTokenIds()
  {
    var user = await _fixture.CreateUserAsync();
    var handler = new JwtSecurityTokenHandler();

    var firstId = handler.ReadJwtToken(await _fixture.TokenService.GenerateAccessToken(user)).Id;
    var secondId = handler.ReadJwtToken(await _fixture.TokenService.GenerateAccessToken(user)).Id;

    Assert.NotEqual(firstId, secondId);
  }

  [Fact]
  public async Task ValidateAccessToken_ValidToken_ReturnsPrincipal()
  {
    var user = await _fixture.CreateUserAsync("alice", "user");
    var token = await _fixture.TokenService.GenerateAccessToken(user);

    var principal = await _fixture.TokenService.ValidateAccessToken(token);

    Assert.NotNull(principal);
    Assert.Equal(user.Id.ToString(), principal.FindFirstValue(ClaimTypes.NameIdentifier));
    Assert.Equal("alice", principal.Identity?.Name);
    Assert.True(principal.IsInRole("user"));
  }

  [Theory]
  [InlineData("")]
  [InlineData("not-a-jwt")]
  [InlineData("a.b.c")]
  public async Task ValidateAccessToken_MalformedToken_ReturnsNull(string token)
  {
    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Fact]
  public async Task ValidateAccessToken_TamperedPayload_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var victim = await _fixture.CreateUserAsync("bob");
    var token = await _fixture.TokenService.GenerateAccessToken(user);

    var parts = token.Split('.');
    var payload = Base64UrlEncoder.Decode(parts[1]).Replace(user.Id.ToString(), victim.Id.ToString());
    var tamperedToken = $"{parts[0]}.{Base64UrlEncoder.Encode(payload)}.{parts[2]}";

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(tamperedToken));
  }

  [Fact]
  public async Task ValidateAccessToken_SignedWithAnotherKey_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var foreignParameters = TokenServiceFixture.CreateValidationParameters("another-secret-key-that-is-long-enough-for-hmac-sha256-and-sha512-signatures");
    var token = CreateToken(user.Id, foreignParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Theory]
  [InlineData("foreign-issuer", TokenServiceFixture.Audience)]
  [InlineData(TokenServiceFixture.Issuer, "foreign-audience")]
  public async Task ValidateAccessToken_WrongIssuerOrAudience_ReturnsNull(string issuer, string audience)
  {
    var user = await _fixture.CreateUserAsync();
    var token = CreateToken(user.Id, _fixture.ValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256,
      issuer: issuer, audience: audience);

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Fact]
  public async Task ValidateAccessToken_OtherHmacAlgorithm_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var token = CreateToken(user.Id, _fixture.ValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha512);

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Fact]
  public async Task ValidateAccessToken_UnsignedToken_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var signedToken = await _fixture.TokenService.GenerateAccessToken(user);

    var payload = signedToken.Split('.')[1];
    var header = Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");

    Assert.Null(await _fixture.TokenService.ValidateAccessToken($"{header}.{payload}."));
  }

  [Fact]
  public async Task ValidateAccessToken_ExpiredToken_ReturnsNullUnlessLifetimeIsIgnored()
  {
    // Expired beyond the one-minute clock skew.
    await using var expiredFixture = TokenServiceFixture.Create(accessTokenExpirationMinutes: -5);
    var user = await expiredFixture.CreateUserAsync();
    var token = await expiredFixture.TokenService.GenerateAccessToken(user);

    Assert.Null(await expiredFixture.TokenService.ValidateAccessToken(token));
    Assert.NotNull(await expiredFixture.TokenService.ValidateAccessToken(token, validateLifetime: false));
  }

  [Fact]
  public async Task ValidateAccessToken_DoesNotChangeSharedValidationParameters()
  {
    var user = await _fixture.CreateUserAsync();
    var token = await _fixture.TokenService.GenerateAccessToken(user);

    await _fixture.TokenService.ValidateAccessToken(token, validateLifetime: false);

    Assert.True(_fixture.ValidationParameters.ValidateLifetime);
  }

  [Fact]
  public async Task ValidateAccessToken_AfterSecurityStampChange_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var token = await _fixture.TokenService.GenerateAccessToken(user);

    await _fixture.UserManager.UpdateSecurityStampAsync(user);

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Fact]
  public async Task ValidateAccessToken_DeletedUser_ReturnsNull()
  {
    var user = await _fixture.CreateUserAsync();
    var token = await _fixture.TokenService.GenerateAccessToken(user);

    await _fixture.UserManager.DeleteAsync(user);

    Assert.Null(await _fixture.TokenService.ValidateAccessToken(token));
  }

  [Fact]
  public async Task IsSecurityStampValid_CurrentStamp_ReturnsTrue()
  {
    var user = await _fixture.CreateUserAsync();
    var stamp = await _fixture.UserManager.GetSecurityStampAsync(user);

    var principal = CreatePrincipal(user.Id, _fixture.TokenService.HashToken(stamp));

    Assert.True(await _fixture.TokenService.IsSecurityStampValid(principal));
  }

  [Fact]
  public async Task IsSecurityStampValid_MissingStampClaim_ReturnsFalse()
  {
    var user = await _fixture.CreateUserAsync();

    Assert.False(await _fixture.TokenService.IsSecurityStampValid(CreatePrincipal(user.Id, stampHash: null)));
  }

  [Fact]
  public async Task IsSecurityStampValid_RawStampInsteadOfHash_ReturnsFalse()
  {
    var user = await _fixture.CreateUserAsync();
    var stamp = await _fixture.UserManager.GetSecurityStampAsync(user);

    Assert.False(await _fixture.TokenService.IsSecurityStampValid(CreatePrincipal(user.Id, stamp)));
  }

  [Fact]
  public async Task IsSecurityStampValid_UnknownUser_ReturnsFalse()
  {
    var principal = CreatePrincipal(Guid.NewGuid(), _fixture.TokenService.HashToken("any-stamp"));

    Assert.False(await _fixture.TokenService.IsSecurityStampValid(principal));
  }

  private static ClaimsPrincipal CreatePrincipal(Guid userId, string? stampHash)
  {
    var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, userId.ToString()) };
    if (stampHash != null) claims.Add(new Claim("sstamp", stampHash));
    return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
  }

  private static string CreateToken(Guid userId, SecurityKey key, string algorithm,
    string issuer = TokenServiceFixture.Issuer, string audience = TokenServiceFixture.Audience)
  {
    var token = new JwtSecurityToken(
      issuer: issuer,
      audience: audience,
      claims: new[] { new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()) },
      expires: DateTime.UtcNow.AddMinutes(5),
      signingCredentials: new SigningCredentials(key, algorithm));
    return new JwtSecurityTokenHandler().WriteToken(token);
  }
}

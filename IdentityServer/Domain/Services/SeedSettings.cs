namespace IdentityServer.Domain.Services;

public class SeedSettings
{
  public List<SeedUser> Users { get; set; } = [];
}

public class SeedUser
{
  public string Username { get; set; } = string.Empty;
  public string Email { get; set; } = string.Empty;
  public string Password { get; set; } = string.Empty;
  public List<string> Roles { get; set; } = [];
}

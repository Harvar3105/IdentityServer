namespace IdentityServer.Domain.Services;

public class SeedSettings
{
  public List<SeedProject> Projects { get; set; } = [];
  public List<SeedUser> Users { get; set; } = [];

  public string? GetInitialRole(string key)
  {
    foreach(var proj in Projects)
    {
      if (proj.API_KEY.Equals(key)) return proj.Roles.Initial;
    }
    return null;
  }
}

public class SeedUser
{
  public string Username { get; set; } = string.Empty;
  public string Email { get; set; } = string.Empty;
  public string Password { get; set; } = string.Empty;
  public List<string> Roles { get; set; } = [];
}

public class SeedRoles
{
  public List<string> Admin { get; set; } = [];
  public List<string> User { get; set; } = [];
  public string Initial { get; set; } = string.Empty;
}

public class SeedProject
{
  public string Name { get; set; } = string.Empty;
  public SeedRoles Roles { get; set; }
  public string API_KEY { get; set; } = string.Empty;
}
namespace IdentityServer.Domain.Services;

public class RoleSettings
{
  public List<string> Available { get; set; } = [];
  public string Initial { get; set; } = string.Empty;
  public string Root { get; set; } = string.Empty;
  public List<string> Managers { get; set; } = [];

  // Identity normalizes role names, so case-sensitive checks would let "admin" bypass a guard on "ADMIN".
  public bool IsAvailable(string role) => Available.Contains(role, StringComparer.OrdinalIgnoreCase);
  public bool IsRoot(string role) => string.Equals(role, Root, StringComparison.OrdinalIgnoreCase);
  public bool IsPrivileged(string role) => IsRoot(role) || Managers.Contains(role, StringComparer.OrdinalIgnoreCase);
}

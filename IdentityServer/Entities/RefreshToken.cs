namespace IdentityServer.Entities;

public class RefreshToken
{
    public Guid Id { get; set; }
    public string Token { get; set; } = Guid.NewGuid().ToString();
    public DateTime Expires { get; set; }
    public bool IsExpired => DateTime.UtcNow >= Expires;
    public DateTime Created { get; set; } = DateTime.UtcNow;
    public string? CreatedByIp { get; set; }
    public string? RevokedByIp { get; set; }
    public DateTime? Revoked { get; set; }
    public bool IsActive => Revoked == null && !IsExpired;

    public string UserId { get; set; }
    public User User { get; set; }
}
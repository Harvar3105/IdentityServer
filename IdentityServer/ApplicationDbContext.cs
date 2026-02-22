using IdentityServer.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer;

public class ApplicationDbContext : IdentityDbContext<User, Role, Guid, UserClaim, IdentityUserRole<Guid>,
  IdentityUserLogin<Guid>, IdentityRoleClaim<Guid>, IdentityUserToken<Guid>>
{
  public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : base(options)
  {
  }

  public DbSet<RefreshToken> RefreshTokens { get; set; }

  protected override void OnModelCreating(ModelBuilder builder)
  {
    base.OnModelCreating(builder);

    builder.Entity<User>()
      .HasMany(u => u.RefreshTokens)
      .WithOne(rt => rt.User)
      .HasForeignKey(rt => rt.UserId)
      .OnDelete(DeleteBehavior.Cascade);

    builder.Entity<IdentityUserLogin<Guid>>(b =>
    {
      b.HasKey(l => new { l.LoginProvider, l.ProviderKey });
    });

    builder.Entity<IdentityUserToken<Guid>>(b =>
    {
      b.HasKey(t => new { t.UserId, t.LoginProvider, t.Name });
    });
  }
}

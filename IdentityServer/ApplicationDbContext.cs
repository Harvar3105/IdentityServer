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
  public DbSet<ProfilePicture> ProfilePictures { get; set; }

  protected override void OnModelCreating(ModelBuilder builder)
  {
    base.OnModelCreating(builder);

    builder.Entity<User>()
      .HasIndex(u => u.NormalizedEmail)
      .IsUnique();

    builder.Entity<User>()
      .HasMany(u => u.RefreshTokens)
      .WithOne(rt => rt.User)
      .HasForeignKey(rt => rt.UserId)
      .OnDelete(DeleteBehavior.Cascade);

    builder.Entity<RefreshToken>(b =>
    {
      b.HasIndex(rt => rt.SessionId);
      // Every refresh-token lookup searches by the hash. A Base64 SHA-256 hash is always 44 characters.
      b.Property(rt => rt.TokenHash).HasMaxLength(44);
      b.HasIndex(rt => rt.TokenHash).IsUnique();
    });

    builder.Entity<User>()
      .HasMany(u => u.Claims)
      .WithOne()
      .HasForeignKey(uc => uc.UserId)
      .IsRequired();

    builder.Entity<ProfilePicture>(b =>
    {
      b.HasKey(p => p.UserId);
      b.HasOne(p => p.User)
        .WithOne(u => u.ProfilePicture)
        .HasForeignKey<ProfilePicture>(p => p.UserId)
        .OnDelete(DeleteBehavior.Cascade);
      b.Property(p => p.ContentType).HasMaxLength(64);
      b.Property(p => p.ContentHash).HasMaxLength(64);
    });

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

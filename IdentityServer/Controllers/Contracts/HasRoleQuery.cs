using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace IdentityServer.Controllers.Contracts;

public class HasRoleQuery
{
  [BindRequired] public Guid UserId { get; init; }
  [Required] public string Role { get; init; } = string.Empty;
}

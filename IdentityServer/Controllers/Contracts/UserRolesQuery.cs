using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace IdentityServer.Controllers.Contracts;

public class UserRolesQuery
{
  [BindRequired] public Guid UserId { get; init; }
}

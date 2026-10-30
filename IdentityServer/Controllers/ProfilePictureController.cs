using IdentityServer.Domain.Services;
using IdentityServer.Entities;
using IdentityServer.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace IdentityServer.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class ProfilePictureController : ControllerBase
{
  private readonly IProfilePictureService _profilePictureService;
  private readonly UserManager<User> _userManager;
  private readonly RoleSettings _roleSettings;
  private readonly ILogger<ProfilePictureController> _logger;

  public ProfilePictureController(IProfilePictureService profilePictureService, UserManager<User> userManager,
    IOptions<RoleSettings> roleSettings, ILogger<ProfilePictureController> logger)
  {
    _profilePictureService = profilePictureService;
    _userManager = userManager;
    _roleSettings = roleSettings.Value;
    _logger = logger;
  }

  [HttpPut]
  [Consumes("multipart/form-data")]
  [TypeFilter<ProfilePictureUploadLimitFilter>]
  // TODO: Add a per-user rate limit for uploads.
  public async Task<IActionResult> Upload(IFormFile file, CancellationToken cancellationToken)
  {
    if (!TryGetCurrentUserId(out var userId)) return Unauthorized();

    await using var content = file.OpenReadStream();
    var result = await _profilePictureService.Upload(userId, content, cancellationToken);

    return result.Error switch
    {
      null => Ok(result.Picture),
      ProfilePictureUploadError.TooLarge => StatusCode(StatusCodes.Status413PayloadTooLarge, "File is too large!"),
      ProfilePictureUploadError.Empty => BadRequest("File is empty!"),
      ProfilePictureUploadError.UnknownFormat => BadRequest("File is not a supported image!"),
      ProfilePictureUploadError.FormatNotAllowed => BadRequest("Image format is not allowed!"),
      ProfilePictureUploadError.DimensionsOutOfRange => BadRequest("Image dimensions are out of the allowed range!"),
      ProfilePictureUploadError.UserNotFound => NotFound("User not found!"),
      _ => throw new InvalidOperationException($"Unhandled upload error {result.Error}.")
    };
  }

  // Anonymous so that client projects can show pictures in <img> tags, which cannot send a bearer token.
  [HttpGet("{userId:guid}")]
  [AllowAnonymous]
  public async Task<IActionResult> Get(Guid userId, CancellationToken cancellationToken)
  {
    var metadata = await _profilePictureService.GetMetadata(userId, cancellationToken);
    if (metadata is null) return NotFound();

    var entityTag = new EntityTagHeaderValue($"\"{metadata.ContentHash}\"");
    var responseHeaders = Response.GetTypedHeaders();
    responseHeaders.ETag = entityTag;
    responseHeaders.LastModified = new DateTimeOffset(DateTime.SpecifyKind(metadata.UpdatedAt, DateTimeKind.Utc));
    Response.Headers.CacheControl = "public, no-cache";
    Response.Headers.XContentTypeOptions = "nosniff";
    Response.Headers.ContentSecurityPolicy = "default-src 'none'; sandbox";

    var ifNoneMatch = Request.GetTypedHeaders().IfNoneMatch;
    if (ifNoneMatch.Any(tag => tag.Equals(EntityTagHeaderValue.Any) || tag.Compare(entityTag, useStrongComparison: false)))
      return StatusCode(StatusCodes.Status304NotModified);

    var picture = await _profilePictureService.Get(userId, cancellationToken);
    if (picture is null) return NotFound();

    return File(picture.Content, picture.ContentType);
  }

  [HttpDelete]
  public async Task<IActionResult> Delete(CancellationToken cancellationToken)
  {
    if (!TryGetCurrentUserId(out var userId)) return Unauthorized();

    return await _profilePictureService.Delete(userId, cancellationToken) ? NoContent() : NotFound();
  }

  // Moderation: root and managers can remove any picture but never replace it, so nobody can put an image
  // on someone else's profile.
  [HttpDelete("{userId:guid}")]
  public async Task<IActionResult> DeleteByModerator(Guid userId, CancellationToken cancellationToken)
  {
    if (!IsModerator()) return Forbid();

    var targetUser = await _userManager.FindByIdAsync(userId.ToString());
    if (targetUser is null) return NotFound();

    if (!User.IsInRole(_roleSettings.Root))
    {
      var targetRoles = await _userManager.GetRolesAsync(targetUser);
      if (targetRoles.Any(_roleSettings.IsPrivileged)) return Forbid();
    }

    if (!await _profilePictureService.Delete(userId, cancellationToken)) return NotFound();

    _logger.LogInformation("Profile picture of user {UserId} was deleted by moderator {ModeratorId}.",
      userId, _userManager.GetUserId(User));
    return NoContent();
  }

  private bool TryGetCurrentUserId(out Guid userId) => Guid.TryParse(_userManager.GetUserId(User), out userId);

  private bool IsModerator() => User.IsInRole(_roleSettings.Root) || _roleSettings.Managers.Any(User.IsInRole);
}

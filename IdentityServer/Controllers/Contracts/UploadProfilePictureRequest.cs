using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Controllers.Contracts;

// Multipart form; the format is detected from the file content, so its name and Content-Type are ignored.
public class UploadProfilePictureRequest
{
  [Required] public IFormFile File { get; init; } = null!;
}

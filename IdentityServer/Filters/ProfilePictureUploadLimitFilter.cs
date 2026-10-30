using IdentityServer.Domain.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace IdentityServer.Filters;

public class ProfilePictureUploadLimitFilter : IResourceFilter
{
  // Room for multipart boundaries and part headers on top of the file itself.
  private const long MultipartOverheadBytes = 16 * 1024;

  private readonly ProfilePictureSettings _settings;

  public ProfilePictureUploadLimitFilter(IOptions<ProfilePictureSettings> settings)
  {
    _settings = settings.Value;
  }

  public void OnResourceExecuting(ResourceExecutingContext context)
  {
    var features = context.HttpContext.Features;

    var bodySizeFeature = features.Get<IHttpMaxRequestBodySizeFeature>();
    if (bodySizeFeature is { IsReadOnly: false })
      bodySizeFeature.MaxRequestBodySize = _settings.MaxSizeBytes + MultipartOverheadBytes;

    var formFeature = features.Get<IFormFeature>();
    if (formFeature?.Form is null)
    {
      features.Set<IFormFeature>(new FormFeature(context.HttpContext.Request, new FormOptions
      {
        MultipartBodyLengthLimit = _settings.MaxSizeBytes + MultipartOverheadBytes
      }));
    }
  }

  public void OnResourceExecuted(ResourceExecutedContext context)
  {
  }
}

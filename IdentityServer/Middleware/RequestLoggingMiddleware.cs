using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IdentityServer.Middleware;

public class RequestLoggingMiddleware
{
  private const string MaskedValue = "***";
  private static readonly string[] SensitiveFieldMarkers = ["password", "token", "secret"];

  private readonly RequestDelegate _next;
  private readonly ILogger<RequestLoggingMiddleware> _logger;

  public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
  {
    _next = next;
    _logger = logger;
  }

  public async Task InvokeAsync(HttpContext context)
  {
    await LogRequestAsync(context);

    await _next(context);

    LogResponse(context);
  }

  private async Task LogRequestAsync(HttpContext context)
  {
    var request = context.Request;
    var sb = new StringBuilder();

    context.Request.EnableBuffering();

    sb.AppendLine("=== INCOMING REQUEST ===");
    sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
    sb.AppendLine($"Method: {request.Method}");
    sb.AppendLine($"Path: {request.Path}");
    sb.AppendLine($"Query String: {request.QueryString}");
    sb.AppendLine($"Scheme: {request.Scheme}");
    sb.AppendLine($"Host: {request.Host}");

    if (request.Headers.Count > 0)
    {
      sb.AppendLine("Headers:");
      foreach (var header in request.Headers)
      {
        var value = IsSensitiveHeader(header.Key) ? MaskedValue : string.Join("; ", header.Value);
        sb.AppendLine($"  {header.Key}: {value}");
      }
    }

    if (request.Method != "GET" && request.Method != "DELETE" && request.ContentLength > 0)
    {
      using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
      var body = await reader.ReadToEndAsync();
      if (!string.IsNullOrWhiteSpace(body))
      {
        sb.AppendLine($"Body: {MaskSensitiveBody(body)}");
      }
      request.Body.Position = 0;
    }

    sb.AppendLine("=== END REQUEST ===");
    _logger.LogInformation(sb.ToString());
  }

  private void LogResponse(HttpContext context)
  {
    var response = context.Response;
    var sb = new StringBuilder();

    sb.AppendLine("=== OUTGOING RESPONSE ===");
    sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
    sb.AppendLine($"Status Code: {response.StatusCode}");
    sb.AppendLine($"Path: {context.Request.Path}");

    if (response.Headers.Count > 0)
    {
      sb.AppendLine("Headers:");
      foreach (var header in response.Headers)
      {
        var value = IsSensitiveHeader(header.Key) ? MaskedValue : string.Join("; ", header.Value);
        sb.AppendLine($"  {header.Key}: {value}");
      }
    }

    sb.AppendLine("=== END RESPONSE ===");
    _logger.LogInformation(sb.ToString());
  }

  private static bool IsSensitiveHeader(string headerName)
  {
    var sensitiveHeaders = new[]
    {
      "authorization",
      "cookie",
      "x-api-key",
      "x-token",
      "password",
      "secret",
      "project"
    };

    return sensitiveHeaders.Contains(headerName.ToLowerInvariant());
  }

  private static string MaskSensitiveBody(string body)
  {
    JsonNode? root;
    try
    {
      root = JsonNode.Parse(body);
    }
    catch (JsonException)
    {
      return "[non-JSON body omitted]";
    }

    // A bare JSON value (e.g. the raw token sent to /api/token/validate) has no field name to classify it by.
    if (root is null or JsonValue) return MaskedValue;

    MaskSensitiveFields(root);
    return root.ToJsonString();
  }

  private static void MaskSensitiveFields(JsonNode node)
  {
    switch (node)
    {
      case JsonObject jsonObject:
        foreach (var propertyName in jsonObject.Select(property => property.Key).ToList())
        {
          if (IsSensitiveField(propertyName))
            jsonObject[propertyName] = MaskedValue;
          else if (jsonObject[propertyName] is { } childNode)
            MaskSensitiveFields(childNode);
        }
        break;
      case JsonArray jsonArray:
        foreach (var itemNode in jsonArray)
        {
          if (itemNode is not null) MaskSensitiveFields(itemNode);
        }
        break;
    }
  }

  private static bool IsSensitiveField(string fieldName)
  {
    return SensitiveFieldMarkers.Any(marker => fieldName.Contains(marker, StringComparison.OrdinalIgnoreCase));
  }
}

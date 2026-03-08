using System.Text;

namespace IdentityServer.Middleware;

public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Логируем входящий запрос
        await LogRequestAsync(context);

        // Вызываем следующий middleware
        await _next(context);

        // Логируем исходящий ответ
        LogResponse(context);
    }

    private async Task LogRequestAsync(HttpContext context)
    {
        var request = context.Request;
        var sb = new StringBuilder();

        sb.AppendLine("=== INCOMING REQUEST ===");
        sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
        sb.AppendLine($"Method: {request.Method}");
        sb.AppendLine($"Path: {request.Path}");
        sb.AppendLine($"Query String: {request.QueryString}");
        sb.AppendLine($"Scheme: {request.Scheme}");
        sb.AppendLine($"Host: {request.Host}");

        // Логируем заголовки
        if (request.Headers.Count > 0)
        {
            sb.AppendLine("Headers:");
            foreach (var header in request.Headers)
            {
                // Скрываем чувствительные данные
                var value = IsSensitiveHeader(header.Key) ? "***" : string.Join("; ", header.Value);
                sb.AppendLine($"  {header.Key}: {value}");
            }
        }

        // Логируем тело запроса для POST/PUT/PATCH
        if (request.Method != "GET" && request.Method != "DELETE" && request.ContentLength > 0)
        {
            request.Body.Position = 0;
            using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            if (!string.IsNullOrWhiteSpace(body))
            {
                sb.AppendLine($"Body: {body}");
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
                var value = IsSensitiveHeader(header.Key) ? "***" : string.Join("; ", header.Value);
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
            "secret"
        };

        return sensitiveHeaders.Contains(headerName.ToLowerInvariant());
    }
}

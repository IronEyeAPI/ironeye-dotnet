using System.Text.Json;

namespace IronEye;

/// <summary>Base of every exception this library throws.</summary>
public class IronEyeException : Exception
{
    public IronEyeException(string message) : base(message) { }

    public IronEyeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>A transport failure, where there is no server verdict to read.</summary>
public sealed class ConnectionException : IronEyeException
{
    public ConnectionException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>The families a caller switches on, rather than a status four refusals share.</summary>
public enum ErrorKind
{
    Unauthenticated,
    Forbidden,
    RateLimited,
    InvalidRequest,
    NotFound,
    Compliance,
    Upstream,
    Server,
}

/// <summary>
/// An error the server described in its response body.
/// </summary>
/// <remarks>
/// <see cref="Retryable"/> is the server's own verdict rather than an inference from the status
/// code: a 429 from a spent monthly allowance is not the same wait as a 429 from a rate limiter,
/// and only the body tells them apart.
/// </remarks>
public sealed class ApiException : IronEyeException
{
    internal ApiException(
        int status,
        string code,
        string message,
        bool retryable,
        string requestId,
        string suggestedAction,
        string doc,
        string? path,
        JsonElement? meta)
        : base($"{code}: {message} (request_id={requestId})")
    {
        Status = status;
        Code = code;
        Retryable = retryable;
        RequestId = requestId;
        SuggestedAction = suggestedAction;
        Doc = doc;
        Path = path;
        Meta = meta;
    }

    public int Status { get; }

    public string Code { get; }

    public bool Retryable { get; }

    public string RequestId { get; }

    public string SuggestedAction { get; }

    public string Doc { get; }

    public string? Path { get; }

    public JsonElement? Meta { get; }

    public ErrorKind Kind => Code switch
    {
        "UNAUTHENTICATED" => ErrorKind.Unauthenticated,
        "FORBIDDEN_SCOPE" or "PLAN_LIMITED" => ErrorKind.Forbidden,
        "RATE_LIMITED" or "QUOTA_EXHAUSTED" or "TENANT_BUSY" => ErrorKind.RateLimited,
        "NOT_FOUND" => ErrorKind.NotFound,
        "COMPLIANCE_REFUSED" or "COLLECTION_BLOCKED" => ErrorKind.Compliance,
        "SOURCE_NOT_CONFIGURED" or "UPSTREAM_REFUSED" or "UPSTREAM_THROTTLED" => ErrorKind.Upstream,
        "INTERNAL" or "DEPENDENCY_UNAVAILABLE" or "SERVER_DRAINING" => ErrorKind.Server,
        _ => ErrorKind.InvalidRequest,
    };

    internal static ApiException From(int status, JsonElement? payload)
    {
        if (payload is { ValueKind: JsonValueKind.Object } body
            && body.TryGetProperty("error", out var error)
            && error.TryGetProperty("code", out var code))
        {
            return new ApiException(
                status,
                code.GetString() ?? "INTERNAL",
                Text(error, "message") ?? "The request failed.",
                error.TryGetProperty("retryable", out var retryable) && retryable.GetBoolean(),
                Text(error, "request_id") ?? "-",
                Text(error, "suggested_action") ?? string.Empty,
                Text(error, "doc") ?? string.Empty,
                Text(error, "path"),
                error.TryGetProperty("meta", out var meta) ? meta.Clone() : null);
        }

        return new ApiException(
            status,
            "INTERNAL",
            $"The server returned {status} with no error body.",
            status >= 500,
            "-",
            "Retry, and quote the status if it persists.",
            string.Empty,
            null,
            null);
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

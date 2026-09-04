using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IronEye;

/// <summary>What a collection call declares about itself.</summary>
/// <remarks>
/// Required on any operation whose <c>personal_data</c> flag is true: the server refuses rather
/// than assumes.
/// </remarks>
public sealed record Declaration(
    string? LegalBasis = null,
    string? Purpose = null,
    string? Controller = null,
    string? BasisEvidence = null,
    string? SpecialCondition = null,
    string? Projection = null)
{
    public static readonly Declaration None = new();

    internal IEnumerable<KeyValuePair<string, string>> Headers()
    {
        var pairs = new (string Name, string? Value)[]
        {
            ("X-Legal-Basis", LegalBasis),
            ("X-Purpose", Purpose),
            ("X-Controller", Controller),
            ("X-Basis-Evidence", BasisEvidence),
            ("X-Special-Condition", SpecialCondition),
            ("X-Projection", Projection),
        };
        foreach (var (name, value) in pairs)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                yield return new KeyValuePair<string, string>(name, value!);
            }
        }
    }
}

/// <summary>Names a person on a platform, for the rights endpoints.</summary>
public sealed record Subject(string Platform, string Identifier, string? Reference = null);

/// <summary>Options for a client. Every field falls back to the environment, then to a default.</summary>
public sealed class IronEyeOptions
{
    public string? ApiKey { get; set; }

    public string? BaseUrl { get; set; }

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(60);

    public int MaxRetries { get; set; } = 2;
}

/// <summary>
/// Official .NET client for the IronEye document intelligence and collection API.
/// </summary>
/// <remarks>
/// <para>
/// Responses come back as <see cref="JsonElement"/>: every module reports a different shape, and a
/// fixed model would refuse to bind the morning after the engine learned to report one more thing.
/// </para>
/// <para>
/// Logging carries the method, route, status, duration and request id. No credential and no payload
/// is ever recorded.
/// </para>
/// </remarks>
[DebuggerDisplay("IronEye {_baseUrl,nq} // managed, awaited, and never leaking a key — Direct Softworks")]
public sealed class IronEyeClient : IDisposable
{
    public const string Version = "1.0.0";

    private const string DefaultBaseUrl = "https://ironeye.org";

    private static readonly HashSet<int> RetryableStatus = [408, 425, 429, 500, 502, 503, 504];

    private static readonly Dictionary<string, string> AnalysisRoutes = new()
    {
        ["analyze"] = "/v1/analyze",
        ["extract"] = "/v1/extract",
        ["classify"] = "/v1/classify",
        ["pii"] = "/v1/pii/analyze",
        ["moderation"] = "/v1/moderation/analyze",
        ["malware"] = "/v1/malware/scan",
        ["secrets"] = "/v1/secrets/scan",
        ["validate"] = "/v1/validate",
        ["deduplicate"] = "/v1/deduplicate",
        ["invoices"] = "/v1/invoices/parse",
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ILogger _log;
    private readonly string _baseUrl;
    private readonly int _maxRetries;

    public IronEyeClient(
        IronEyeOptions? options = null,
        HttpClient? httpClient = null,
        ILogger<IronEyeClient>? logger = null)
    {
        options ??= new IronEyeOptions();
        var key = options.ApiKey ?? Environment.GetEnvironmentVariable("IRONEYE_API_KEY");
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("An API key is required: set ApiKey, or IRONEYE_API_KEY.");
        }

        _baseUrl = (options.BaseUrl
                    ?? Environment.GetEnvironmentVariable("IRONEYE_BASE_URL")
                    ?? DefaultBaseUrl).TrimEnd('/');
        _maxRetries = options.MaxRetries;
        _log = logger ?? NullLogger<IronEyeClient>.Instance;
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient();
        _http.Timeout = options.Timeout;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"ironeye-dotnet/{Version}");
    }

    // -- analysis ------------------------------------------------------------

    public Task<JsonElement> AnalyzeAsync(object request, string? idempotencyKey = null, CancellationToken ct = default)
        => AnalysisAsync("analyze", request, idempotencyKey, ct);

    public Task<JsonElement> ExtractAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("extract", request, null, ct);

    public Task<JsonElement> ClassifyAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("classify", request, null, ct);

    public Task<JsonElement> PiiAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("pii", request, null, ct);

    public Task<JsonElement> ModerationAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("moderation", request, null, ct);

    public Task<JsonElement> MalwareAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("malware", request, null, ct);

    public Task<JsonElement> SecretsAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("secrets", request, null, ct);

    public Task<JsonElement> ValidateAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("validate", request, null, ct);

    public Task<JsonElement> DeduplicateAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("deduplicate", request, null, ct);

    public Task<JsonElement> InvoicesAsync(object request, CancellationToken ct = default)
        => AnalysisAsync("invoices", request, null, ct);

    private Task<JsonElement> AnalysisAsync(string name, object request, string? key, CancellationToken ct)
    {
        var headers = key is null
            ? Array.Empty<KeyValuePair<string, string>>()
            : [new KeyValuePair<string, string>("Idempotency-Key", key)];
        return SendAsync(HttpMethod.Post, AnalysisRoutes[name], null, request, headers, ct);
    }

    // -- jobs ------------------------------------------------------------------

    public Task<JsonElement> CreateJobAsync(object request, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, "/v1/jobs", null, request, [], ct);

    public Task<JsonElement> JobAsync(string jobId, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, $"/v1/jobs/{Uri.EscapeDataString(jobId)}", null, null, [], ct);

    public Task DeleteJobAsync(string jobId, CancellationToken ct = default)
        => SendAsync(HttpMethod.Delete, $"/v1/jobs/{Uri.EscapeDataString(jobId)}", null, null, [], ct);

    /// <summary>
    /// Polls until the job settles. Nothing in the service dispatches to a callback URL, so polling
    /// is the whole asynchronous contract.
    /// </summary>
    public async Task<JsonElement> AwaitJobAsync(
        string jobId,
        TimeSpan? interval = null,
        TimeSpan? limit = null,
        CancellationToken ct = default)
    {
        var step = interval ?? TimeSpan.FromSeconds(2);
        var deadline = DateTime.UtcNow + (limit ?? TimeSpan.FromMinutes(5));
        while (true)
        {
            var job = await JobAsync(jobId, ct).ConfigureAwait(false);
            var status = job.TryGetProperty("status", out var value) ? value.GetString() : null;
            if (status is "completed" or "failed")
            {
                return job;
            }

            if (DateTime.UtcNow + step > deadline)
            {
                throw new IronEyeException($"Job {jobId} was still {status} when the wait elapsed.");
            }

            await Task.Delay(step, ct).ConfigureAwait(false);
        }
    }

    // -- collection ------------------------------------------------------------

    public Task<JsonElement> CatalogueAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/harvest/catalogue", null, null, [], ct);

    public Task<JsonElement> OperationsAsync(string? platform = null, CancellationToken ct = default)
        => SendAsync(
            HttpMethod.Get,
            "/v1/harvest/operations",
            platform is null ? null : new Dictionary<string, string> { ["platform"] = platform },
            null,
            [],
            ct);

    public Task<JsonElement> OperationAsync(string opId, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, $"/v1/harvest/operations/{Uri.EscapeDataString(opId)}", null, null, [], ct);

    /// <summary>
    /// Runs one operation, addressed by its own route as the catalogue gives it:
    /// <c>/v1/harvest/reddit/subreddit</c>, say.
    /// </summary>
    public Task<JsonElement> CollectAsync(
        string path,
        IDictionary<string, string>? parameters = null,
        Declaration? declaration = null,
        CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, path, parameters, null, (declaration ?? Declaration.None).Headers(), ct);

    /// <summary>
    /// <see cref="CollectAsync"/> for the operations the registry declares as POST. The parameters
    /// are identical; only where they travel changes.
    /// </summary>
    public Task<JsonElement> CollectPostAsync(
        string path,
        IDictionary<string, string>? parameters = null,
        Declaration? declaration = null,
        CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, path, null, parameters ?? new Dictionary<string, string>(),
            (declaration ?? Declaration.None).Headers(), ct);

    // -- data subject rights ---------------------------------------------------

    public Task<JsonElement> GdprNoticeAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/gdpr/notice", null, null, [], ct);

    public Task<JsonElement> ErasureAsync(Subject subject, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, "/v1/gdpr/erasure", null, SubjectBody(subject), [], ct);

    public Task<JsonElement> ObjectionAsync(Subject subject, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, "/v1/gdpr/objections", null, SubjectBody(subject), [], ct);

    public Task<JsonElement> AccessRequestAsync(Subject subject, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, "/v1/gdpr/access", null, SubjectBody(subject), [], ct);

    public Task<JsonElement> SuppressionAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/gdpr/suppression", null, null, [], ct);

    public Task UnsuppressAsync(string subjectKey, CancellationToken ct = default)
        => SendAsync(HttpMethod.Delete, $"/v1/gdpr/suppression/{Uri.EscapeDataString(subjectKey)}", null, null, [], ct);

    private static Dictionary<string, string> SubjectBody(Subject subject)
    {
        var body = new Dictionary<string, string>
        {
            ["platform"] = subject.Platform,
            ["identifier"] = subject.Identifier,
        };
        if (subject.Reference is not null)
        {
            body["reference"] = subject.Reference;
        }

        return body;
    }

    // -- service ---------------------------------------------------------------

    public Task<JsonElement> HealthAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/healthz", null, null, [], ct);

    public Task<JsonElement> ReadyAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/readyz", null, null, [], ct);

    public Task<JsonElement> FeaturesAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/features", null, null, [], ct);

    public Task<JsonElement> StatusAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/status", null, null, [], ct);

    public Task<JsonElement> AuditHeadAsync(CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "/v1/audit/head", null, null, [], ct);

    // -- transport -------------------------------------------------------------

    private async Task<JsonElement> SendAsync(
        HttpMethod method,
        string path,
        IDictionary<string, string>? query,
        object? body,
        IEnumerable<KeyValuePair<string, string>> headers,
        CancellationToken ct)
    {
        var url = _baseUrl + path + QueryString(query);
        var headerList = headers.ToList();
        Exception? last = null;

        for (var attempt = 0; attempt <= _maxRetries; attempt++)
        {
            // A new message per attempt: an HttpRequestMessage cannot be sent twice.
            using var request = new HttpRequestMessage(method, url);
            foreach (var (name, value) in headerList)
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }

            if (body is not null)
            {
                request.Content = JsonContent.Create(body, options: SerializerOptions);
            }

            var started = Stopwatch.GetTimestamp();
            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            }
            catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                last = new ConnectionException($"{method} {path} failed.", failure);
                if (attempt >= _maxRetries)
                {
                    throw last;
                }

                await PauseAsync(attempt, null, "CONNECTION", path, ct).ConfigureAwait(false);
                continue;
            }

            using (response)
            {
                var payload = await ReadAsync(response, ct).ConfigureAwait(false);
                _log.LogDebug(
                    "ironeye {Method} {Path} -> {Status} in {DurationMs}ms (request_id={RequestId})",
                    method,
                    path,
                    (int)response.StatusCode,
                    (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                    response.Headers.TryGetValues("x-request-id", out var ids) ? ids.FirstOrDefault() : "-");

                if (response.IsSuccessStatusCode)
                {
                    return payload ?? default;
                }

                var failure = ApiException.From((int)response.StatusCode, payload);
                if (attempt >= _maxRetries || !failure.Retryable || !RetryableStatus.Contains(failure.Status))
                {
                    throw failure;
                }

                last = failure;
                await PauseAsync(attempt, response.Headers.RetryAfter?.Delta, failure.Code, path, ct)
                    .ConfigureAwait(false);
            }
        }

        throw last ?? new IronEyeException($"{method} {path} exhausted its retries.");
    }

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static async Task<JsonElement?> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(text).RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Retry-After is the server's own number, so it wins over the backoff curve.</summary>
    private async Task PauseAsync(int attempt, TimeSpan? retryAfter, string code, string path, CancellationToken ct)
    {
        var wait = retryAfter ?? TimeSpan.FromMilliseconds(250 * Math.Pow(2, attempt) + Random.Shared.Next(250));
        _log.LogWarning("ironeye {Path} retrying after {Code} in {WaitMs}ms", path, code, (int)wait.TotalMilliseconds);
        await Task.Delay(wait, ct).ConfigureAwait(false);
    }

    private static string QueryString(IDictionary<string, string>? query)
    {
        if (query is null || query.Count == 0)
        {
            return string.Empty;
        }

        var pairs = query.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}");
        return "?" + string.Join("&", pairs);
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }
}

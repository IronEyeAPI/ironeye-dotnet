# IronEye for .NET

The official .NET client for the [IronEye](https://ironeye.org) API: document
analysis over bytes you send, and normalised collection from public sources,
behind one key.

```sh
dotnet add package IronEye
```

## Features

- Every analysis route, the async job path with `AwaitJobAsync`, the collection
  catalogue and the data-subject-rights endpoints.
- `CancellationToken` on every call.
- `ApiException` carrying the code, retry verdict, request id and suggested
  action, with an `ErrorKind` to switch on.
- Retries on the server's own `Retryable` flag, honouring `Retry-After`.
- `Microsoft.Extensions.Logging.Abstractions` only, so the host picks the sink.
  No credential, no payload.

Full documentation, including every endpoint and every option, is at
**https://ironeye.org/docs/sdk/dotnet**.

---

Direct Softworks · [MIT](LICENSE) · issues and pull requests welcome

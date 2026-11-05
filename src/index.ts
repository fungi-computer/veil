/** Sanitized public failure; an optional cause is retained internally only. */
export class VeilError extends Error {
  public constructor(
    public readonly code:
      | "denied"
      | "invalid_input"
      | "invalid_completion"
      | "invalid_response"
      | "conflict"
      | "ambiguous"
      | "expired"
      | "unavailable"
      | "github_not_configured"
      | "cancelled"
      | "reconnect_required"
      | "unsupported"
      /** GitHub refused the repository: it is outside the App installation. */
      | "repository_not_installed"
      /** The provider's rate limit refused this request; retry later. */
      | "rate_limited",
    cause?: unknown,
  ) {
    super(code);
    this.name = "VeilError";
    if (cause !== undefined)
      Object.defineProperty(this, "cause", { value: cause, enumerable: false });
  }
}

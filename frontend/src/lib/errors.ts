import { ApiError } from "./api";

export interface ErrorDescription {
  title: string;
  message: string;
  retryable: boolean;
}

export function describeError(err: unknown): ErrorDescription {
  if (!(err instanceof ApiError)) {
    return { title: "Something went wrong", message: "An unexpected error occurred.", retryable: true };
  }
  switch (err.kind) {
    case "unauthorized":
      return { title: "Signed out", message: "Your session has ended. Please sign in again.", retryable: false };
    case "forbidden":
      return { title: "Not permitted", message: "You do not have permission to do this.", retryable: false };
    case "unsupported_media":
      return { title: "Request rejected", message: "The server rejected the request format (415).", retryable: false };
    case "rate_limited": {
      const wait = err.retryAfterSeconds;
      return {
        title: "Too many requests",
        message:
          wait !== undefined
            ? `Too many requests. Try again in ${wait} second${wait === 1 ? "" : "s"}.`
            : "Too many requests. Try again later.",
        retryable: true,
      };
    }
    case "network":
      return { title: "Server unreachable", message: "Cannot reach the server. Check your connection and retry.", retryable: true };
    case "server":
      return { title: "Server error", message: err.message, retryable: true };
    case "schema":
      return { title: "Unexpected response", message: err.message, retryable: true };
    default:
      return { title: "Request failed", message: err.message, retryable: false };
  }
}

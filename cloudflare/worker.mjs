// USBAY Gateway - Cloudflare Worker front for the containerized FastAPI app.
// All requests are proxied unchanged to the container; no governance logic
// lives here and no request is answered without the gateway (fail-closed).
import { Container, getContainer } from "@cloudflare/containers";

export class UsbayGateway extends Container {
  defaultPort = 5000;
  sleepAfter = "10m";

  constructor(ctx, env) {
    super(ctx, env);
    // Pass the expected release commit into the container so the gateway's
    // fail-closed startup check (governance/deployment_sync.py) can enforce
    // deployed-commit verification in production. The value is injected at
    // deploy time via `wrangler deploy --var EXPECTED_GIT_COMMIT:<sha>`.
    this.envVars = {
      PORT: "5000",
      USBAY_EXPECTED_GIT_COMMIT: (env && env.EXPECTED_GIT_COMMIT) || "",
    };
  }

  // The gateway performs fail-closed governance verification while
  // importing, so cold starts exceed the library's default 20s port
  // wait. Extend the wait instead of serving a fallback (fail-closed).
  async startAndWaitForPorts(portsOrArgs, cancellationOptions, startOptions) {
    const extra = { instanceGetTimeoutMS: 60_000, portReadyTimeoutMS: 240_000 };
    if (portsOrArgs && typeof portsOrArgs === "object" && !Array.isArray(portsOrArgs)) {
      return super.startAndWaitForPorts({
        ...portsOrArgs,
        cancellationOptions: { ...extra, ...(portsOrArgs.cancellationOptions ?? {}) },
      });
    }
    return super.startAndWaitForPorts(
      portsOrArgs,
      { ...extra, ...(cancellationOptions ?? {}) },
      startOptions,
    );
  }
}

export default {
  async fetch(request, env) {
    try {
      // Forward the original public hostname so the gateway's host-surface
      // router can map each governed subdomain to its dedicated surface.
      const hostname = new URL(request.url).hostname.toLowerCase();
      const forwarded = new Request(request);
      forwarded.headers.set("X-USBAY-Host", hostname);
      return await getContainer(env.USBAY_GATEWAY).fetch(forwarded);
    } catch (err) {
      // Fail closed: never serve a fallback response for the gateway.
      return new Response("USBAY gateway unavailable (fail-closed)", { status: 503 });
    }
  },
};

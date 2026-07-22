// USBAY Gateway - Cloudflare Worker front for the containerized FastAPI app.
// All requests are proxied unchanged to the container; no governance logic
// lives here and no request is answered without the gateway (fail-closed).
import { Container, getContainer } from "@cloudflare/containers";

export class UsbayGateway extends Container {
  defaultPort = 5000;
  sleepAfter = "10m";
  envVars = { PORT: "5000" };
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

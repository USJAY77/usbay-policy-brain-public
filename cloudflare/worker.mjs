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
      return await getContainer(env.USBAY_GATEWAY).fetch(request);
    } catch (err) {
      // Fail closed: never serve a fallback response for the gateway.
      return new Response("USBAY gateway unavailable (fail-closed)", { status: 503 });
    }
  },
};

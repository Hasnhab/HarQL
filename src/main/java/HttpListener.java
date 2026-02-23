package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;

/**
 * HTTP handler that intercepts GraphQL and JavaScript traffic for harvesting.
 */

public class HttpListener implements HttpHandler {
    private final MontoyaApi api;
    private final InMemoryEngine engine;

    public HttpListener(MontoyaApi api, InMemoryEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            String url = requestToBeSent.url().toLowerCase();
            String body = requestToBeSent.bodyToString();
            String contentType = requestToBeSent.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                    .map(h -> h.value())
                    .findFirst()
                    .orElse("");

            boolean isGraphQL = url.contains("graphql") ||
                    (contentType.contains("application/json") &&
                     (body.contains("\"query\"") || body.contains("\"variables\"")));

            if (isGraphQL && body != null && !body.isEmpty()) {
                engine.ingestGraphql(body, null, null);
            }
        } catch (Exception ignored) {}

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived event) {
        try {
            String body = event.bodyToString();
            if (body == null || body.isEmpty()) {
                return ResponseReceivedAction.continueWith(event);
            }
            String contentType = event.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                    .map(h -> h.value())
                    .findFirst()
                    .orElse("");
            String url = event.initiatingRequest().url();
            if ((contentType.contains("javascript") || url.endsWith(".js")) &&
                body != null && !body.isEmpty()) {
                
                // Use ingestJs (corrected method name
                engine.ingestJs(
                        url,
                        event.initiatingRequest().httpService().host(),
                        body
                );
            }
        } catch (Exception ignored) {}
        return ResponseReceivedAction.continueWith(event);
    }
}
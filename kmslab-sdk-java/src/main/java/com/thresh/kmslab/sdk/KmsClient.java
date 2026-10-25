package com.thresh.kmslab.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thresh.kmslab.core.Purpose;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Typed client for the KMSLab HTTP API.
 *
 * <p>The token is supplied through a {@link Supplier} and resolved on every request. That is not
 * convenience: capability tokens live at most five minutes, so a client that caches one for its
 * lifetime would fail after the first few calls, and a client that refreshes on its own schedule
 * would hold a token longer than the issuer intended. Delegating to the caller keeps refresh where
 * the identity lives.
 *
 * @author threshbyte
 */
public final class KmsClient implements AutoCloseable {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final URI baseUri;
    private final HttpClient http;
    private final Supplier<String> tokenSupplier;
    private final Duration requestTimeout;
    private final ObjectMapper mapper = new ObjectMapper();

    private KmsClient(Builder builder) {
        this.baseUri = URI.create(builder.baseUrl.endsWith("/")
                ? builder.baseUrl : builder.baseUrl + "/");
        this.http = builder.httpClient != null ? builder.httpClient
                : HttpClient.newBuilder().connectTimeout(builder.connectTimeout).build();
        this.tokenSupplier = Objects.requireNonNull(builder.tokenSupplier,
                "a token supplier is required");
        this.requestTimeout = builder.requestTimeout;
    }

    public static Builder builder(String baseUrl) {
        return new Builder(baseUrl);
    }

    public static final class Builder {

        private final String baseUrl;
        private Supplier<String> tokenSupplier;
        private HttpClient httpClient;
        private Duration requestTimeout = DEFAULT_TIMEOUT;
        private Duration connectTimeout = DEFAULT_TIMEOUT;

        private Builder(String baseUrl) {
            this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
        }

        /** Supplies the bearer token for each request. Called once per call. */
        public Builder token(Supplier<String> supplier) {
            this.tokenSupplier = supplier;
            return this;
        }

        /**
         * A fixed token. Fine for tests and short-lived tools; a long-running service should use
         * {@link #token(Supplier)} because a capability token expires within minutes.
         */
        public Builder token(String fixedToken) {
            this.tokenSupplier = () -> fixedToken;
            return this;
        }

        public Builder httpClient(HttpClient client) {
            this.httpClient = client;
            return this;
        }

        public Builder requestTimeout(Duration timeout) {
            this.requestTimeout = timeout;
            return this;
        }

        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = timeout;
            return this;
        }

        public KmsClient build() {
            return new KmsClient(this);
        }
    }

    /* ------------------------------------------------------------------ keys */

    public Key createKey(String alias, boolean exportAllowed) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", alias);
        body.put("exportAllowed", exportAllowed);
        return call("/v1/keys", body, Key.class);
    }

    public Key rotateKey(UUID keyId) {
        return call("/v1/keys/" + keyId + "/rotate", Map.of(), Key.class);
    }

    public Key disableKey(UUID keyId) {
        return call("/v1/keys/" + keyId + "/disable", Map.of(), Key.class);
    }

    public Key enableKey(UUID keyId) {
        return call("/v1/keys/" + keyId + "/enable", Map.of(), Key.class);
    }

    public Key cancelDeletion(UUID keyId) {
        return call("/v1/keys/" + keyId + "/cancel-deletion", Map.of(), Key.class);
    }

    /**
     * Schedules deletion.
     *
     * @param approver               a person other than the token subject; the server rejects
     *                               self-approval
     * @param referencingCiphertexts from an actual scan, not from the caller's belief; the server
     *                               refuses to proceed while this is positive unless forced
     */
    public Key scheduleDeletion(UUID keyId, int coolingDays, String approver,
                                long referencingCiphertexts, boolean force) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("coolingDays", coolingDays);
        body.put("approver", approver);
        body.put("referencingCiphertexts", referencingCiphertexts);
        body.put("force", force);
        return call("/v1/keys/" + keyId + "/schedule-deletion", body, Key.class);
    }

    /** Irreversible. Every ciphertext under the key becomes unreadable. */
    public Key purgeKey(UUID keyId) {
        return call("/v1/keys/" + keyId + "/purge", Map.of(), Key.class);
    }

    /* ------------------------------------------------------------------ crypto */

    /** Encrypts under the key's current version and returns a {@code kms1.} envelope. */
    public String encrypt(UUID keyId, Map<String, String> ctx, byte[] plaintext) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyId", keyId.toString());
        body.put("ctx", ctx);
        body.put("plaintextBase64", Base64.getEncoder().encodeToString(plaintext));
        return call("/v1/encrypt", body, JsonNode.class).get("envelope").asText();
    }

    /**
     * Decrypts an envelope.
     *
     * <p>The key is taken from the ciphertext header, so the caller cannot accidentally ask for a
     * key that does not match the data. A purpose is mandatory: the server records it in the audit
     * chain, which is what makes "why was this read" answerable later.
     */
    public byte[] decrypt(Map<String, String> ctx, String envelope, Purpose purpose) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("purpose", purpose.name());
        body.put("ctx", ctx);
        body.put("envelope", envelope);
        String encoded = call("/v1/decrypt", body, JsonNode.class)
                .get("plaintextBase64").asText();
        return Base64.getDecoder().decode(encoded);
    }

    /** Requests a data key in mode B. Only works for keys created with export allowed. */
    public ExportedDataKey generateDataKey(UUID keyId, Map<String, String> ctx) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyId", keyId.toString());
        body.put("ctx", ctx);
        JsonNode node = call("/v1/datakeys", body, JsonNode.class);
        return new ExportedDataKey(
                Base64.getDecoder().decode(node.get("plaintextDekBase64").asText()),
                node.get("wrappedDek").asText());
    }

    /** Liveness check. Needs no token. */
    public boolean healthy() {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/v1/health"))
                .timeout(requestTimeout)
                .GET()
                .build();
        try {
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return response.statusCode() == 200;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /* ------------------------------------------------------------------ transport */

    private <T> T call(String path, Object body, Class<T> responseType) {
        String token = tokenSupplier.get();
        if (token == null || token.isBlank()) {
            throw new KmsClientException(401, "NO_TOKEN", null,
                    "the token supplier returned nothing");
        }
        byte[] payload;
        try {
            payload = mapper.writeValueAsBytes(body);
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode request", e);
        }
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve(path.substring(1)))
                .timeout(requestTimeout)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                .build();

        HttpResponse<byte[]> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new KmsClientException(0, "TRANSPORT", null, "request failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new KmsClientException(0, "INTERRUPTED", null, "request interrupted");
        }

        int status = response.statusCode();
        byte[] responseBody = response.body();
        if (status < 200 || status >= 300) {
            throw toException(status, responseBody);
        }
        if (responseType == JsonNode.class) {
            try {
                return responseType.cast(mapper.readTree(responseBody));
            } catch (IOException e) {
                throw new IllegalStateException("cannot parse response", e);
            }
        }
        try {
            return mapper.readValue(responseBody, responseType);
        } catch (IOException e) {
            throw new IllegalStateException("cannot parse response", e);
        }
    }

    /**
     * Builds the typed exception from the server's error envelope.
     *
     * <p>Deliberately falls back to a generic code rather than echoing an unparsed body: the body
     * could contain anything if the peer is not actually our server.
     */
    private KmsClientException toException(int status, byte[] body) {
        try {
            JsonNode error = mapper.readTree(body).path("error");
            String code = error.path("code").asText("UNKNOWN");
            String reason = error.hasNonNull("reason") ? error.get("reason").asText() : null;
            String message = error.path("message").asText("");
            return new KmsClientException(status, code, reason, message);
        } catch (IOException e) {
            return new KmsClientException(status, "UNPARSEABLE_ERROR", null,
                    "server returned " + status + " with an unreadable body");
        }
    }

    @Override
    public void close() {
        http.close();
    }
}

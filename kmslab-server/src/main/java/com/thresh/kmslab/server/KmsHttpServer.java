package com.thresh.kmslab.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.thresh.kmslab.core.Action;
import com.thresh.kmslab.core.Approval;
import com.thresh.kmslab.core.DataKey;
import com.thresh.kmslab.core.EnvelopeBroker;
import com.thresh.kmslab.core.KeyService;
import com.thresh.kmslab.core.KmsErrorCode;
import com.thresh.kmslab.core.KmsException;
import com.thresh.kmslab.core.ManagedKey;
import com.thresh.kmslab.core.Principal;
import com.thresh.kmslab.core.Purpose;
import com.thresh.kmslab.core.TokenAuthority;
import com.thresh.kmslab.core.TokenException;
import com.thresh.kmslab.envelope.Ctx;
import com.thresh.kmslab.envelope.EnvelopeException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * HTTP surface over {@link KeyService} and {@link EnvelopeBroker}.
 *
 * <p>Built on the JDK HTTP server and virtual threads: no web framework, so the request path stays
 * readable and there is no hidden filter chain to reason about.
 *
 * <p>Authentication is a bearer capability token (see {@link TokenAuthority}). There is no static
 * access token and no token issuance endpoint: a caller must already hold a token minted by a
 * trusted issuer process.
 *
 * @author threshbyte
 */
public final class KmsHttpServer {

    /** Hard cap on request bodies. Encrypting larger blobs belongs in mode B, not in one call. */
    private static final int MAX_BODY_BYTES = 1 << 20;

    private final KeyService keys;
    private final EnvelopeBroker broker;
    private final TokenAuthority authority;
    private final HttpServer server;

    private KmsHttpServer(KeyService keys, EnvelopeBroker broker, TokenAuthority authority,
                          HttpServer server) {
        this.keys = keys;
        this.broker = broker;
        this.authority = authority;
        this.server = server;
    }

    /** Starts on an ephemeral or explicit port. Port 0 asks the OS for a free one. */
    public static KmsHttpServer start(int port, KeyService keys, EnvelopeBroker broker,
                                      TokenAuthority authority) throws IOException {
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 64);
        KmsHttpServer kms = new KmsHttpServer(keys, broker, authority, http);
        http.createContext("/", kms::handle);
        http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        http.start();
        return kms;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + port();
    }

    public void stop() {
        server.stop(0);
    }

    /* ------------------------------------------------------------------ dispatch */

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            if (path.equals("/v1/health") && method.equals("GET")) {
                write(exchange, 200, Map.of("status", "ok"));
                return;
            }

            TokenAuthority.VerifiedIdentity identity = authenticate(exchange);
            route(exchange, method, path, identity);
        } catch (ApiException e) {
            writeError(exchange, e.status(), e.code(), null, e.getMessage());
        } catch (TokenException e) {
            writeError(exchange, 401, e.reason().name(), null, e.getMessage());
        } catch (KmsException e) {
            // code carries the category (e.g. INVALID_STATE), reason the specific cause
            // (e.g. KEY_STATE_DISABLED). Clients can branch on the category and display the rest.
            writeError(exchange, statusFor(e.code()), e.code().name(), e.reason(), e.getMessage());
        } catch (EnvelopeException e) {
            writeError(exchange, 400, e.code().name(), null, e.getMessage());
        } catch (RuntimeException e) {
            // Never echo an unexpected exception message: it may carry internals.
            writeError(exchange, 500, "INTERNAL", null, "internal error");
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange, String method, String path,
                       TokenAuthority.VerifiedIdentity identity) throws IOException {
        if (!method.equals("POST")) {
            throw new ApiException(405, "METHOD_NOT_ALLOWED", "only POST is supported here");
        }
        if (path.equals("/v1/keys")) {
            createKey(exchange, identity);
            return;
        }
        if (path.startsWith("/v1/keys/")) {
            String[] parts = path.substring("/v1/keys/".length()).split("/");
            if (parts.length == 2) {
                UUID keyId = parseUuid(parts[0]);
                keyOperation(exchange, identity, keyId, parts[1]);
                return;
            }
        }
        if (path.equals("/v1/encrypt")) {
            encrypt(exchange, identity);
            return;
        }
        if (path.equals("/v1/decrypt")) {
            decrypt(exchange, identity);
            return;
        }
        if (path.equals("/v1/datakeys")) {
            dataKey(exchange, identity);
            return;
        }
        throw new ApiException(404, "NO_ROUTE", "no route for " + path);
    }

    /* ------------------------------------------------------------------ keys */

    private void createKey(HttpExchange exchange, TokenAuthority.VerifiedIdentity identity)
            throws IOException {
        CreateKeyRequest req = Json.read(readBody(exchange), CreateKeyRequest.class);
        Principal actor = principal(identity);
        // The tenant comes from the token, never from the request body: a caller must not be able
        // to choose which tenant it writes into.
        ManagedKey key = keys.create(actor, req.alias(), identity.tenant(), req.exportAllowed());
        write(exchange, 201, KeyResponse.of(key));
    }

    private void keyOperation(HttpExchange exchange, TokenAuthority.VerifiedIdentity identity,
                              UUID keyId, String operation) throws IOException {
        Principal actor = principal(identity);
        byte[] body = readBody(exchange);

        switch (operation) {
            case "rotate" -> {
                CapabilityGuard.check(identity, Action.ROTATE, keyId, null, null);
                write(exchange, 200, KeyResponse.of(keys.rotate(actor, keyId)));
            }
            case "disable" -> {
                CapabilityGuard.check(identity, Action.DISABLE, keyId, null, null);
                write(exchange, 200, KeyResponse.of(keys.disable(actor, keyId)));
            }
            case "enable" -> {
                CapabilityGuard.check(identity, Action.ENABLE, keyId, null, null);
                write(exchange, 200, KeyResponse.of(keys.enable(actor, keyId)));
            }
            case "cancel-deletion" -> {
                CapabilityGuard.check(identity, Action.CANCEL_DELETION, keyId, null, null);
                write(exchange, 200, KeyResponse.of(keys.cancelDeletion(actor, keyId)));
            }
            case "purge" -> {
                CapabilityGuard.check(identity, Action.PURGE, keyId, null, null);
                keys.purge(actor, keyId);
                write(exchange, 200, KeyResponse.of(keys.get(keyId)));
            }
            case "schedule-deletion" -> {
                CapabilityGuard.check(identity, Action.SCHEDULE_DELETION, keyId, null, null);
                ScheduleDeletionRequest req = Json.read(body, ScheduleDeletionRequest.class);
                Approval approval = new Approval(identity.subject(), req.approver());
                ManagedKey key = keys.scheduleDeletion(actor, keyId,
                        Duration.ofDays(req.coolingDays()), approval,
                        req.referencingCiphertexts(), req.force());
                write(exchange, 200, KeyResponse.of(key));
            }
            default -> throw new ApiException(404, "NO_ROUTE", "unknown operation: " + operation);
        }
    }

    /* ------------------------------------------------------------------ crypto */

    private void encrypt(HttpExchange exchange, TokenAuthority.VerifiedIdentity identity)
            throws IOException {
        EncryptRequest req = Json.read(readBody(exchange), EncryptRequest.class);
        UUID keyId = parseUuid(req.keyId());
        Ctx ctx = toCtx(req.ctx());
        CapabilityGuard.check(identity, Action.ENCRYPT, keyId, ctx.asMap().get("column"), null);

        byte[] plaintext = decodeBase64(req.plaintextBase64(), "plaintextBase64");
        String envelope = broker.encrypt(principal(identity), keyId, ctx, plaintext);
        write(exchange, 200, Map.of("envelope", envelope));
    }

    private void decrypt(HttpExchange exchange, TokenAuthority.VerifiedIdentity identity)
            throws IOException {
        DecryptRequest req = Json.read(readBody(exchange), DecryptRequest.class);
        Ctx ctx = toCtx(req.ctx());
        Purpose purpose = parsePurpose(req.purpose());
        CapabilityGuard.check(identity, Action.DECRYPT, null, ctx.asMap().get("column"), purpose);

        byte[] plaintext = broker.decrypt(principal(identity), purpose, ctx, req.envelope(),
                CapabilityGuard.restrictedKey(identity));
        write(exchange, 200, Map.of("plaintextBase64",
                Base64.getEncoder().encodeToString(plaintext)));
    }

    private void dataKey(HttpExchange exchange, TokenAuthority.VerifiedIdentity identity)
            throws IOException {
        DataKeyRequest req = Json.read(readBody(exchange), DataKeyRequest.class);
        UUID keyId = parseUuid(req.keyId());
        Ctx ctx = toCtx(req.ctx());
        CapabilityGuard.check(identity, Action.GENERATE_DATA_KEY, keyId,
                ctx.asMap().get("column"), null);

        DataKey dk = broker.generateDataKey(principal(identity), keyId, ctx);
        write(exchange, 200, Map.of(
                "plaintextDekBase64", Base64.getEncoder().encodeToString(dk.plaintextDek()),
                "wrappedDek", dk.wrappedDek().encode()));
    }

    /* ------------------------------------------------------------------ helpers */

    private TokenAuthority.VerifiedIdentity authenticate(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            throw new ApiException(401, "MISSING_TOKEN", "Authorization: Bearer <token> required");
        }
        return authority.verify(header.substring("Bearer ".length()).trim());
    }

    private static Principal principal(TokenAuthority.VerifiedIdentity identity) {
        return new Principal(identity.subject(), identity.tenant());
    }

    private static byte[] readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            byte[] body = in.readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
                throw new ApiException(413, "BODY_TOO_LARGE",
                        "request body exceeds " + MAX_BODY_BYTES + " bytes");
            }
            return body;
        }
    }

    private static UUID parseUuid(String raw) {
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, "BAD_UUID", "not a UUID: " + raw);
        }
    }

    private static Purpose parsePurpose(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ApiException(400, "PURPOSE_REQUIRED", "purpose is required for decryption");
        }
        try {
            return Purpose.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, "BAD_PURPOSE", "unknown purpose: " + raw);
        }
    }

    private static byte[] decodeBase64(String value, String field) {
        if (value == null) {
            throw new ApiException(400, "MISSING_FIELD", field + " is required");
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, "BAD_BASE64", field + " is not valid base64");
        }
    }

    private static Ctx toCtx(Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            throw new ApiException(400, "MISSING_CTX", "ctx is required");
        }
        try {
            return Ctx.builder().putAll(map).build();
        } catch (EnvelopeException e) {
            throw new ApiException(400, e.code().name(), e.getMessage());
        }
    }

    private static int statusFor(KmsErrorCode code) {
        return switch (code) {
            case NOT_FOUND -> 404;
            case FORBIDDEN, APPROVAL_REQUIRED -> 403;
            case INVALID_STATE, CONFLICT, REFERENCES_EXIST, COOLING_PERIOD_ACTIVE -> 409;
            case BAD_REQUEST -> 400;
        };
    }

    private static void write(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = Json.write(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private void writeError(HttpExchange exchange, int status, String code, String reason,
                            String message) throws IOException {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", code);
        if (reason != null) {
            error.put("reason", reason);
        }
        error.put("message", message == null ? "" : message);
        if (exchange.getResponseCode() != -1) {
            return; // response already started; cannot replace it
        }
        write(exchange, status, Map.of("error", error));
    }

    /* ------------------------------------------------------------------ payloads */

    record CreateKeyRequest(String alias, boolean exportAllowed) {
    }

    record ScheduleDeletionRequest(long coolingDays, String approver,
                                   long referencingCiphertexts, boolean force) {
    }

    record EncryptRequest(String keyId, Map<String, String> ctx, String plaintextBase64) {
    }

    record DecryptRequest(String purpose, Map<String, String> ctx, String envelope) {
    }

    record DataKeyRequest(String keyId, Map<String, String> ctx) {
    }

    record KeyResponse(String keyId, String alias, String tenant, String state,
                       int currentVersion, boolean exportAllowed, String deleteAfter) {

        static KeyResponse of(ManagedKey key) {
            return new KeyResponse(key.keyId().toString(), key.alias(), key.tenant(),
                    key.state().name(), key.currentVersion(), key.exportAllowed(),
                    key.deleteAfter() == null ? null : key.deleteAfter().toString());
        }
    }

    /** Route table, exposed for tests and documentation. */
    public static List<String> routes() {
        return List.of(
                "GET  /v1/health",
                "POST /v1/keys",
                "POST /v1/keys/{id}/rotate",
                "POST /v1/keys/{id}/disable",
                "POST /v1/keys/{id}/enable",
                "POST /v1/keys/{id}/schedule-deletion",
                "POST /v1/keys/{id}/cancel-deletion",
                "POST /v1/keys/{id}/purge",
                "POST /v1/encrypt",
                "POST /v1/decrypt",
                "POST /v1/datakeys");
    }
}

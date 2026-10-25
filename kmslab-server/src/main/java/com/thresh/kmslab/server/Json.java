package com.thresh.kmslab.server;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * JSON plumbing. One mapper, configured to reject unknown fields so a typo in a client cannot be
 * silently ignored.
 *
 * @author threshbyte
 */
final class Json {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    private Json() {
    }

    static <T> T read(byte[] body, Class<T> type) {
        try {
            return MAPPER.readValue(body, type);
        } catch (Exception e) {
            throw new ApiException(400, "MALFORMED_JSON", "request body is not valid JSON: "
                    + e.getMessage());
        }
    }

    static byte[] write(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (Exception e) {
            throw new IllegalStateException("cannot serialise response", e);
        }
    }
}

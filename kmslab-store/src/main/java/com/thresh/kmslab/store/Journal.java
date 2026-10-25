package com.thresh.kmslab.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Append-only JSON-lines journal, forced to disk on every append.
 *
 * <p>Chosen over a database for this stage because the audit chain is already an append-only
 * structure: a log file is the natural shape, not a compromise. It also makes the durability
 * contract explicit — {@link #append} returns only after {@code fsync}.
 *
 * <p>A crash can leave a half-written last line. That line is discarded on read, because a
 * truncated record was never acknowledged to the caller.
 *
 * @author threshbyte
 */
public final class Journal implements Closeable {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte NEWLINE = '\n';

    private final Path file;
    private final FileChannel channel;

    private Journal(Path file, FileChannel channel) {
        this.file = file;
        this.channel = channel;
    }

    public static Journal open(Path file) throws IOException {
        Files.createDirectories(file.toAbsolutePath().getParent());
        // READ cannot be combined with APPEND; reads go through Files.readAllBytes instead.
        FileChannel channel = FileChannel.open(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        return new Journal(file, channel);
    }

    public Path path() {
        return file;
    }

    /**
     * Appends one record and forces it to disk before returning.
     *
     * <p>Durability before acknowledgement is the whole point: a key create that is acknowledged
     * and then lost on restart would leave ciphertext whose key no longer exists.
     */
    public synchronized void append(String type, Map<String, Object> payload) {
        ObjectNode record = MAPPER.createObjectNode();
        record.put("type", type);
        record.set("payload", MAPPER.valueToTree(payload));
        byte[] line = (record + "\n").getBytes(StandardCharsets.UTF_8);
        try {
            ByteBuffer buffer = ByteBuffer.wrap(line);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(false);
        } catch (IOException e) {
            throw new JournalException("cannot append to " + file, e);
        }
    }

    /**
     * Reads every complete record. A trailing partial line is dropped: it was never acknowledged.
     */
    public List<Record> readAll() {
        byte[] bytes;
        try {
            bytes = Files.exists(file) ? Files.readAllBytes(file) : new byte[0];
        } catch (IOException e) {
            throw new JournalException("cannot read " + file, e);
        }
        List<Record> records = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == NEWLINE) {
                String line = new String(bytes, start, i - start, StandardCharsets.UTF_8);
                start = i + 1;
                if (!line.isBlank()) {
                    records.add(parse(line, records.size() + 1));
                }
            }
        }
        return records;
    }

    private Record parse(String line, int index) {
        try {
            JsonNode node = MAPPER.readTree(line);
            String type = node.path("type").asText();
            if (type.isBlank()) {
                throw new JournalException("record " + index + " has no type", null);
            }
            return new Record(type, node.path("payload"));
        } catch (IOException e) {
            // A complete line that cannot be parsed is real corruption, not a torn write.
            throw new JournalException("record " + index + " is not valid JSON in " + file, e);
        }
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            throw new JournalException("cannot close " + file, e);
        }
    }

    /** One journal record. */
    public record Record(String type, JsonNode payload) {

        public String string(String field) {
            return payload.path(field).asText();
        }

        public int integer(String field) {
            return payload.path(field).asInt();
        }

        public boolean bool(String field) {
            return payload.path(field).asBoolean();
        }

        public boolean has(String field) {
            return payload.hasNonNull(field);
        }
    }

    /** Wraps I/O and corruption failures. Corrupted state must stop the process, not degrade it. */
    public static class JournalException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public JournalException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

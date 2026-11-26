package io.coroot.agent;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import javax.net.ssl.SSLEngineResult;

public class EngineHooks {
    private static final int MAX_PAYLOAD_SIZE = 1024;
    private static final int RECORD_TAG_SIZE = 24;
    private static final long NONE = -1;

    public static long mark(ByteBuffer[] bufs, int offset, int length) {
        try {
            if (bufs == null || offset < 0 || length < 0 || offset > bufs.length - length) return NONE;
            for (int i = offset; i < offset + length; i++) {
                ByteBuffer b = bufs[i];
                if (b == null) return NONE;
                if (b.hasRemaining()) return ((long) i << 32) | b.position();
            }
        } catch (Throwable ignored) {
        }
        return NONE;
    }

    public static long recordTag(ByteBuffer src) {
        try {
            if (src == null || src.remaining() < RECORD_TAG_SIZE) return 0;
            int pos = src.position();
            long a = src.getLong(pos), b = src.getLong(pos + 8), c = src.getLong(pos + 16);
            if (src.order() == ByteOrder.BIG_ENDIAN) {
                a = Long.reverseBytes(a);
                b = Long.reverseBytes(b);
                c = Long.reverseBytes(c);
            }
            return a ^ Long.rotateLeft(b, 17) ^ Long.rotateLeft(c, 31);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    public static void onWrap(Object engine, SSLEngineResult result, ByteBuffer[] srcs, long mark) {
        try {
            if (result == null || mark == NONE) return;
            int consumed = result.bytesConsumed();
            if (consumed <= 0) return;
            ByteBuffer b = srcs[(int) (mark >>> 32)];
            int start = (int) mark;
            int len = Math.min(consumed, b.position() - start);
            if (len <= 0) return;
            int id = System.identityHashCode(engine);
            if (b.hasArray()) {
                NativeBridge.tlsEngineWrite(id, b.array(), b.arrayOffset() + start, len);
            } else if (b.isDirect()) {
                NativeBridge.tlsEngineWriteDirect(id, b, start, len);
            } else {
                NativeBridge.tlsEngineWrite(id, copy(b, start, len), 0, len);
            }
        } catch (Throwable ignored) {
        }
    }

    public static void onUnwrap(Object engine, SSLEngineResult result, ByteBuffer[] dsts, long mark, long tag) {
        try {
            if (result == null || result.bytesConsumed() <= 0) return;
            int id = System.identityHashCode(engine);
            int len = 0, start = 0;
            ByteBuffer b = null;
            if (mark != NONE && result.bytesProduced() > 0) {
                b = dsts[(int) (mark >>> 32)];
                start = (int) mark;
                len = Math.min(result.bytesProduced(), b.position() - start);
            }

            if (len <= 0) {
                NativeBridge.tlsEngineRead(id, tag, null, 0, 0);
            } else if (b.hasArray()) {
                NativeBridge.tlsEngineRead(id, tag, b.array(), b.arrayOffset() + start, len);
            } else if (b.isDirect()) {
                NativeBridge.tlsEngineReadDirect(id, tag, b, start, len);
            } else {
                NativeBridge.tlsEngineRead(id, tag, copy(b, start, len), 0, len);
            }
        } catch (Throwable ignored) {
        }
    }

    private static byte[] copy(ByteBuffer b, int start, int len) {
        byte[] data = new byte[Math.min(len, MAX_PAYLOAD_SIZE)];
        ByteBuffer d = b.duplicate();
        d.position(start);
        d.get(data);
        return data;
    }
}

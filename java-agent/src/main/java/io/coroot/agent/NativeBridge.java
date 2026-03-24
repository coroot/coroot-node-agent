package io.coroot.agent;

public class NativeBridge {
    public static synchronized boolean load(String path) {
        try {
            System.load(path);
            return true;
        } catch (UnsatisfiedLinkError e) {
            if (e.getMessage() != null && e.getMessage().contains("already loaded")) return true;
            System.err.println("[coroot] native load failed: " + e.getMessage());
            return false;
        }
    }

    public static native void tlsWriteEnter(byte[] data, int offset, int length);
    public static native void tlsReadExit(byte[] data, int offset, int length);
}

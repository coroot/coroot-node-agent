package io.coroot.agent;

import java.lang.instrument.Instrumentation;

public class TlsAgent {
    private static volatile boolean initialized = false;

    public static void premain(String args, Instrumentation inst) {
        initialize(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) {
        initialize(args, inst);
    }

    private static synchronized void initialize(String nativeLibPath, Instrumentation inst) {
        if (initialized) return;

        System.out.println("[coroot] Initializing Java TLS agent");

        if (nativeLibPath == null || nativeLibPath.isEmpty()) return;
        if (!NativeBridge.load(nativeLibPath)) return;

        inst.addTransformer(new SslTransformer(), true);
        try {
            for (Class<?> cls : inst.getAllLoadedClasses()) {
                if (SslTransformer.isTargetClass(cls.getName()) && inst.isModifiableClass(cls)) {
                    inst.retransformClasses(cls);
                }
            }
        } catch (Exception e) {
            System.err.println("[coroot] retransform failed: " + e.getMessage());
        }

        initialized = true;
        System.out.println("[coroot] Java TLS agent initialized successfully");
    }
}

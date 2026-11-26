package io.coroot.agent;

import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;

public class SslTransformer implements ClassFileTransformer {
    private static final String[] OUTPUT_CLASSES = {
            "sun/security/ssl/SSLSocketImpl$AppOutputStream",
            "sun/security/ssl/AppOutputStream"
    };
    private static final String[] INPUT_CLASSES = {
            "sun/security/ssl/SSLSocketImpl$AppInputStream",
            "sun/security/ssl/AppInputStream"
    };

    private static final String ENGINE_CLASS = "sun/security/ssl/SSLEngineImpl";
    private static final String ENGINE_WRAP_DESC =
            "([Ljava/nio/ByteBuffer;IILjava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;";
    private static final String ENGINE_UNWRAP_DESC =
            "(Ljava/nio/ByteBuffer;[Ljava/nio/ByteBuffer;II)Ljavax/net/ssl/SSLEngineResult;";
    private static final String ENGINE_MARK_DESC = "([Ljava/nio/ByteBuffer;II)J";
    private static final String ENGINE_TAG_DESC = "(Ljava/nio/ByteBuffer;)J";
    private static final String ENGINE_WRAP_HOOK_DESC =
            "(Ljava/lang/Object;Ljavax/net/ssl/SSLEngineResult;[Ljava/nio/ByteBuffer;J)V";
    private static final String ENGINE_UNWRAP_HOOK_DESC =
            "(Ljava/lang/Object;Ljavax/net/ssl/SSLEngineResult;[Ljava/nio/ByteBuffer;JJ)V";
    private static final String HOOKS = "io/coroot/agent/EngineHooks";

    public static boolean isTargetClass(String name) {
        String n = name.replace('.', '/');
        if (n.equals(ENGINE_CLASS)) return true;
        for (String c : OUTPUT_CLASSES) if (n.equals(c)) return true;
        for (String c : INPUT_CLASSES) if (n.equals(c)) return true;
        return false;
    }

    private static boolean isOutputStream(String name) {
        for (String c : OUTPUT_CLASSES) if (name.equals(c)) return true;
        return false;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> cls,
                            ProtectionDomain pd, byte[] bytecode) {
        if (className == null) return null;
        boolean engine = className.equals(ENGINE_CLASS);
        boolean out = isOutputStream(className);
        boolean in = false;
        for (String c : INPUT_CLASSES) if (className.equals(c)) { in = true; break; }
        if (!out && !in && !engine) return null;

        try {
            ClassReader cr = new ClassReader(bytecode);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            ClassVisitor cv;
            if (engine) {
                Map<String, Integer> maxLocals = new HashMap<>();
                cr.accept(new MaxLocalsCollector(maxLocals), 0);
                cv = new EngineVisitor(cw, maxLocals);
            } else {
                cv = out ? new WriteVisitor(cw) : new ReadVisitor(cw);
            }
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static class WriteVisitor extends ClassVisitor {
        WriteVisitor(ClassWriter cw) { super(Opcodes.ASM9, cw); }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
            if (!"write".equals(name) || !"([BII)V".equals(desc)) return mv;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitCode() {
                    super.visitCode();
                    Label tryStart = new Label(), tryEnd = new Label(), handler = new Label(), done = new Label();
                    mv.visitTryCatchBlock(tryStart, tryEnd, handler, "java/lang/Throwable");
                    mv.visitLabel(tryStart);
                    mv.visitVarInsn(Opcodes.ALOAD, 1);
                    mv.visitVarInsn(Opcodes.ILOAD, 2);
                    mv.visitVarInsn(Opcodes.ILOAD, 3);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/coroot/agent/NativeBridge", "tlsWriteEnter", "([BII)V", false);
                    mv.visitLabel(tryEnd);
                    mv.visitJumpInsn(Opcodes.GOTO, done);
                    mv.visitLabel(handler);
                    mv.visitInsn(Opcodes.POP);
                    mv.visitLabel(done);
                }
            };
        }
    }

    private static class ReadVisitor extends ClassVisitor {
        ReadVisitor(ClassWriter cw) { super(Opcodes.ASM9, cw); }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
            if (!"read".equals(name) || !"([BII)I".equals(desc)) return mv;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitInsn(int opcode) {
                    if (opcode == Opcodes.IRETURN) {
                        mv.visitVarInsn(Opcodes.ISTORE, 4);
                        Label tryStart = new Label(), tryEnd = new Label(), handler = new Label(), done = new Label();
                        mv.visitTryCatchBlock(tryStart, tryEnd, handler, "java/lang/Throwable");
                        mv.visitLabel(tryStart);
                        mv.visitVarInsn(Opcodes.ILOAD, 4);
                        Label skip = new Label();
                        mv.visitJumpInsn(Opcodes.IFLE, skip);
                        mv.visitVarInsn(Opcodes.ALOAD, 1);
                        mv.visitVarInsn(Opcodes.ILOAD, 2);
                        mv.visitVarInsn(Opcodes.ILOAD, 4);
                        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/coroot/agent/NativeBridge", "tlsReadExit", "([BII)V", false);
                        mv.visitLabel(skip);
                        mv.visitLabel(tryEnd);
                        mv.visitJumpInsn(Opcodes.GOTO, done);
                        mv.visitLabel(handler);
                        mv.visitInsn(Opcodes.POP);
                        mv.visitLabel(done);
                        mv.visitVarInsn(Opcodes.ILOAD, 4);
                    }
                    super.visitInsn(opcode);
                }
            };
        }
    }

    private static boolean isEngineWrap(String name, String desc) {
        return "wrap".equals(name) && ENGINE_WRAP_DESC.equals(desc);
    }

    private static boolean isEngineUnwrap(String name, String desc) {
        return "unwrap".equals(name) && ENGINE_UNWRAP_DESC.equals(desc);
    }

    private static class MaxLocalsCollector extends ClassVisitor {
        private final Map<String, Integer> maxLocals;

        MaxLocalsCollector(Map<String, Integer> maxLocals) {
            super(Opcodes.ASM9);
            this.maxLocals = maxLocals;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            if (!isEngineWrap(name, desc) && !isEngineUnwrap(name, desc)) return null;
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitMaxs(int maxStack, int locals) {
                    maxLocals.put(name + desc, locals);
                }
            };
        }
    }

    private static class EngineVisitor extends ClassVisitor {
        private final Map<String, Integer> maxLocals;

        EngineVisitor(ClassWriter cw, Map<String, Integer> maxLocals) {
            super(Opcodes.ASM9, cw);
            this.maxLocals = maxLocals;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
            final boolean wrap = isEngineWrap(name, desc);
            Integer locals = maxLocals.get(name + desc);
            if ((!wrap && !isEngineUnwrap(name, desc)) || locals == null) return mv;
            final int bufs = wrap ? 1 : 2;
            final int markVar = locals, tagVar = locals + 2, resultVar = locals + 4;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitCode() {
                    super.visitCode();
                    mv.visitLdcInsn(-1L);
                    mv.visitVarInsn(Opcodes.LSTORE, markVar);
                    mv.visitInsn(Opcodes.LCONST_0);
                    mv.visitVarInsn(Opcodes.LSTORE, tagVar);
                    Label tryStart = new Label(), tryEnd = new Label(), handler = new Label(), done = new Label();
                    mv.visitTryCatchBlock(tryStart, tryEnd, handler, "java/lang/Throwable");
                    mv.visitLabel(tryStart);
                    mv.visitVarInsn(Opcodes.ALOAD, bufs);
                    mv.visitVarInsn(Opcodes.ILOAD, bufs + 1);
                    mv.visitVarInsn(Opcodes.ILOAD, bufs + 2);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "mark", ENGINE_MARK_DESC, false);
                    mv.visitVarInsn(Opcodes.LSTORE, markVar);
                    if (!wrap) {
                        mv.visitVarInsn(Opcodes.ALOAD, 1);
                        mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "recordTag", ENGINE_TAG_DESC, false);
                        mv.visitVarInsn(Opcodes.LSTORE, tagVar);
                    }
                    mv.visitLabel(tryEnd);
                    mv.visitJumpInsn(Opcodes.GOTO, done);
                    mv.visitLabel(handler);
                    mv.visitInsn(Opcodes.POP);
                    mv.visitLabel(done);
                }

                @Override
                public void visitInsn(int opcode) {
                    if (opcode == Opcodes.ARETURN) {
                        mv.visitVarInsn(Opcodes.ASTORE, resultVar);
                        Label tryStart = new Label(), tryEnd = new Label(), handler = new Label(), done = new Label();
                        mv.visitTryCatchBlock(tryStart, tryEnd, handler, "java/lang/Throwable");
                        mv.visitLabel(tryStart);
                        mv.visitVarInsn(Opcodes.ALOAD, 0);
                        mv.visitVarInsn(Opcodes.ALOAD, resultVar);
                        if (wrap) {
                            mv.visitVarInsn(Opcodes.ALOAD, bufs);
                            mv.visitVarInsn(Opcodes.LLOAD, markVar);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "onWrap", ENGINE_WRAP_HOOK_DESC, false);
                        } else {
                            mv.visitVarInsn(Opcodes.ALOAD, bufs);
                            mv.visitVarInsn(Opcodes.LLOAD, markVar);
                            mv.visitVarInsn(Opcodes.LLOAD, tagVar);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "onUnwrap", ENGINE_UNWRAP_HOOK_DESC, false);
                        }
                        mv.visitLabel(tryEnd);
                        mv.visitJumpInsn(Opcodes.GOTO, done);
                        mv.visitLabel(handler);
                        mv.visitInsn(Opcodes.POP);
                        mv.visitLabel(done);
                        mv.visitVarInsn(Opcodes.ALOAD, resultVar);
                    }
                    super.visitInsn(opcode);
                }
            };
        }
    }
}

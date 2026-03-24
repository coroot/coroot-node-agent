package io.coroot.agent;

import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class SslTransformer implements ClassFileTransformer {
    private static final String[] OUTPUT_CLASSES = {
            "sun/security/ssl/SSLSocketImpl$AppOutputStream",
            "sun/security/ssl/AppOutputStream"
    };
    private static final String[] INPUT_CLASSES = {
            "sun/security/ssl/SSLSocketImpl$AppInputStream",
            "sun/security/ssl/AppInputStream"
    };

    public static boolean isTargetClass(String name) {
        String n = name.replace('.', '/');
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
        boolean out = isOutputStream(className);
        boolean in = !out;
        for (String c : INPUT_CLASSES) if (className.equals(c)) { in = true; break; }
        if (!out && !in) return null;

        try {
            ClassReader cr = new ClassReader(bytecode);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            cr.accept(out ? new WriteVisitor(cw) : new ReadVisitor(cw), ClassReader.EXPAND_FRAMES);
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
}

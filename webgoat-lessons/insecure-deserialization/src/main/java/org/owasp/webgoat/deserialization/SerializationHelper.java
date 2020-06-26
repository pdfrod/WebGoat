package org.owasp.webgoat.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.util.Base64;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.*;

public class SerializationHelper {

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    @SuppressFBWarnings(value="OBJECT_DESERIALIZATION",
                        justification="Only whitelisted classes are allowed to be deserialized")
    public static Object fromString(String s, Set whitelist) throws IOException,
            ClassNotFoundException {

        Object ret = null;
        byte[] data = Base64.getDecoder().decode(s);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
            try (WhitelistedObjectInputStream ois = new WhitelistedObjectInputStream(bais, whitelist)) {
                ret = ois.readObject();
            }
        }
        return ret;
    }

    public static String toString(Serializable o) throws IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static String show() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(-8699352886133051976L);
        dos.close();
        byte[] longBytes = baos.toByteArray();
        return bytesToHex(longBytes);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // Copied from:
    // https://wiki.sei.cmu.edu/confluence/display/java/SER12-J.+Prevent+deserialization+of+untrusted+data
    static class WhitelistedObjectInputStream extends ObjectInputStream {
        public Set whitelist;

        public WhitelistedObjectInputStream(InputStream inputStream, Set wl) throws IOException {
            super(inputStream);
            whitelist = wl;
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass cls) throws IOException, ClassNotFoundException {
            if (!whitelist.contains(cls.getName())) {
                throw new InvalidClassException("Unexpected serialized class", cls.getName());
            }
            return super.resolveClass(cls);
        }
    }
}

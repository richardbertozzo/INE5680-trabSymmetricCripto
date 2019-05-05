package trabsymmetriccripto;

import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import org.apache.commons.codec.binary.Base64;

public class Encryptor {

    private final Cipher cipher;

    public Encryptor() throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());

        this.cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
    }

    public String cifrarMsg(SecretKeySpec key, IvParameterSpec iv, String message) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encrypted = cipher.doFinal(message.getBytes());

            return Base64.encodeBase64String(encrypted);
        } catch (Exception e) {
            System.err.println(e);
        }

        return null;
    }

    public String decifrarMsg(SecretKeySpec key, IvParameterSpec ivSpec, String message) throws Exception {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] original = cipher.doFinal(message.getBytes());

            return new String(original);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }

        return null;
    }
}

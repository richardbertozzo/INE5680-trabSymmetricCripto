package trabsymmetriccripto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.util.Enumeration;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

public class KeyStoreAdapter {

    private KeyStore keyStore;
    private String fileName;

    public KeyStoreAdapter(String masterPassword, String fileName) throws Exception {
        // Install Provider FIPS
        Security.addProvider(new BouncyCastleFipsProvider());

        // Adicionado para resolver problema da lentidao no Linux - Sugerido por Marcio Sagaz
        CryptoServicesRegistrar.setSecureRandom(
                FipsDRBG.SHA512_HMAC.fromEntropySource(
                        new BasicEntropySourceProvider(new SecureRandom(), true)
                ).build(null, false)
        );

        this.fileName = fileName;
        // Criar o keystore no diretorio atual
        this.keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        // Cria do zero o keystore
        this.keyStore.load(null, null);

        // Armazena a senha mestre do keystore
        this.keyStore.store(new FileOutputStream(fileName), masterPassword.toCharArray());
    }

    public void storeSecretKey(String storePassword, SecretKey secretKey, String alias)
            throws GeneralSecurityException, IOException {
        char[] passwordChar = storePassword.toCharArray();

        keyStore.setKeyEntry(alias, secretKey, passwordChar, null);
        keyStore.store(new FileOutputStream(this.fileName), passwordChar);
    }

    public String storeIv(String storePassword, byte[] iv, String alias)
            throws GeneralSecurityException, IOException {
        char[] passwordChar = storePassword.toCharArray();

        return null;
    }

    public SecretKey getSecretKey(String keyAlias, String password) throws Exception {
        char[] keyPassword = password.toCharArray();
        KeyStore.ProtectionParameter entryPassword
                = new KeyStore.PasswordProtection(keyPassword);

        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) this.keyStore.getEntry(keyAlias, entryPassword);

        return secretKeyEntry.getSecretKey();
    }

    public SecretKey getIv(String keyAlias, String password) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        char[] keyPassword = password.toCharArray();
        KeyStore.ProtectionParameter entryPassword
                = new KeyStore.PasswordProtection(keyPassword);

        KeyStore.Entry entry = this.keyStore.getEntry(keyAlias, entryPassword);

        return null;
    }

    public void printKeyStore() throws Exception {
        System.out.println("KeyStore type: " + this.keyStore.getType());

        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String elem = aliases.nextElement();
            if (keyStore.isKeyEntry(elem)) {
                System.out.println("Chave = " + elem);
            } else {
                if (keyStore.isCertificateEntry(elem)) {
                    System.out.println("Certificado = " + elem);
                    Certificate cert = keyStore.getCertificate(elem);
                    System.out.println("Chave publica guardada no certificado:" + cert.getPublicKey());
                    System.out.println("Tipo do certificado:" + cert.getType());
                }
            }
        }
    }
}

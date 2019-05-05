package trabsymmetriccripto;

import Utils.PBKDF2Util;
import Utils.StringUtils;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class Main {
    
    private static String sendMessage(KeyStoreAdapter keyStore, Encryptor encryptor) throws Exception {
        String message = StringUtils.getStringFromInput("Digite a mensagem que deseja enviar: ");
        String password = StringUtils.getStringFromInput("Digite uma senha para criptografar a sua mensagem: ");
        String aliasKey = StringUtils.getStringFromInput("Digite um alias para guardar sua chave (ex: senha1): ");
        
        String salt = PBKDF2Util.getSalt();
        SecretKey generateDerivedKey = PBKDF2Util.generateDerivedKey(password, salt, 10000);
        System.err.println("");
        System.err.println("Chave gerada: " + StringUtils.keyToString(generateDerivedKey));
        
        keyStore.storeSecretKey(password, generateDerivedKey, aliasKey);
        
        byte[] ivBytes = PBKDF2Util.getIv();
        System.out.println("IV gerado: " + StringUtils.toHex(ivBytes));
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        String encryptedMessage = encryptor.cifrarMsg((SecretKeySpec) generateDerivedKey, iv, message);
        System.out.println("encrypted message: " + encryptedMessage);
        
        return StringUtils.toHex(ivBytes) + encryptedMessage;
    }
    
    private static String receiveMessage(KeyStoreAdapter keyStore, String encryptedMessage, Encryptor encryptor) throws Exception {
        String password = StringUtils.getStringFromInput("Digite uma senha para descriptografar a mensagem: ");
        String aliasKey = StringUtils.getStringFromInput("Digite um alias da chave (ex: senha1): ");

        // decifragem
        SecretKey secretKey = keyStore.getSecretKey(aliasKey, password);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        System.err.println("Key decifragem: " + StringUtils.keyToString(secretKeySpec));
        
        System.err.println("Iv dec: " + encryptedMessage.substring(0, 32));
        byte[] ivBytes = Hex.decodeHex(encryptedMessage.substring(0, 32).toCharArray());
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        String message = encryptedMessage.substring(32, encryptedMessage.length());
        
        String decryptedMessage = encryptor.decifrarMsg(secretKeySpec, iv, message);
        
        return decryptedMessage;
    }
    
    private static void executeConversation() throws Exception {
        Encryptor encryptor = new Encryptor();
        
        System.err.println("----------------------");
        System.err.println("Criptografia simetrica");
        System.err.println("----------------------");

        // Key Store
        String fileName = "keystore.bcfks";
        String masterPassword = StringUtils.getStringFromInput("Digite a senha mestre do Key Store: ");
        KeyStoreAdapter keyStore = new KeyStoreAdapter(masterPassword, fileName);
        
        System.err.println("Você é quem?");
        System.err.println("Digite a opção: ");
        System.err.println("1 - Alice");
        System.err.println("2 - Bob");
        System.err.println("3 - Ana");
        System.err.println("4 - Pedro");
        String option = StringUtils.getStringFromInput(null);
        System.err.println("Opção: " + option);
        
        String ivMoreEncryptedMessage = sendMessage(keyStore, encryptor);
        System.err.println("Iv and message: " + ivMoreEncryptedMessage);
        
        keyStore.printKeyStore();

        // decifragem
        String decryptedMessage = receiveMessage(keyStore, ivMoreEncryptedMessage, encryptor);
        System.err.println("Mensagem decifrada: " + decryptedMessage);
    }
    
    public static void main(String[] args) throws Exception {
        executeConversation();
    }
}

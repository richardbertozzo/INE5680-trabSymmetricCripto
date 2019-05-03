package trabsymmetriccripto;

import Utils.PBKDF2Util;
import Utils.StringUtils;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class Main {

    private static void saveKey() {

    }

    private static void cifrarMsg() {

    }

    private static String decifrarMsg() {
        return "";
    }

    private static String getPasswordFromInput(String msg) {
        Scanner input = new Scanner(System.in);
        System.out.println(msg);
        return input.nextLine();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {
        PBKDF2Util pbdk2Util = new PBKDF2Util();

        // gerando salt
        String salt = pbdk2Util.getSalt();
        System.err.println("Salt: " + salt);

        String password = getPasswordFromInput("Digite a senha: ");

        SecretKey generateDerivedKey = PBKDF2Util.generateDerivedKey(password, salt, 10000);
        System.err.println("Key: " + StringUtils.keyToString(generateDerivedKey));

        // Key Store
        String fileName = "keystore.bcfks";
        String masterPassword = getPasswordFromInput("Digite a senha mestre: ");
        KeyStoreAdapter keyStore = new KeyStoreAdapter(masterPassword, fileName);

        keyStore.storeSecretKey(password, generateDerivedKey, "aeskey1");
        keyStore.printKeyStore();
    }
}

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
    
    private static String getPasswordFromInput() {
        Scanner input = new Scanner(System.in);
        System.out.println("Digite a senha: ");
        return input.nextLine();
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException {
        PBKDF2Util pbdk2Util = new PBKDF2Util();

        // gerando salt
        String salt = pbdk2Util.getSalt();
        System.err.println("Salt: " + salt);

        String password = getPasswordFromInput();
        
        SecretKey generateDerivedKey = PBKDF2Util.generateDerivedKey(password, salt, 10000);
        System.err.println("Key: " + StringUtils.keyToString(generateDerivedKey));
    }
}

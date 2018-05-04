import java.io.OutputStream;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        String encryptedFilePath = "encryptedFile";
        String publicKeyFilePath = "testPublic.key";
        String privateKeyFilePath = "testPrivate.key";
        String passphrase = "yourPassphrase";
        String decryptedFilePath = "decryptedFile";

        OutputStream encOut = PgpHelper.encryptStream(encryptedFilePath, publicKeyFilePath);
        encOut.write("line1".getBytes());
        System.out.println("Written line 1");
        encOut.write("\nline2".getBytes());
        System.out.println("Written line 2");
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter any string to terminate");
        sc.next();
        encOut.write("\nline3".getBytes());
        System.out.println("Written line 3");
        encOut.write("\nline4".getBytes());
        System.out.println("Written line 4");
        encOut.close();
        PgpHelper.decryptStream(encryptedFilePath, decryptedFilePath, privateKeyFilePath, passphrase);
    }
}

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.*;

public class PgpHelper {

    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        InputStream decoderStream = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        PGPPublicKey pgpPublicKey = null;

        Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator = pgpPub.getKeyRings();

        while (pgpPublicKey == null && pgpPublicKeyRingIterator.hasNext()) {
            PGPPublicKeyRing kRing = pgpPublicKeyRingIterator.next();
            Iterator<PGPPublicKey> publicKeys = kRing.getPublicKeys();
            while (pgpPublicKey == null && publicKeys.hasNext()) {
                PGPPublicKey publicKey = publicKeys.next();

                if (publicKey.isEncryptionKey()) {
                    pgpPublicKey = publicKey;
                }
            }
        }

        if (pgpPublicKey == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return pgpPublicKey;
    }


    public static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        PGPSecretKey pgpSecretKeyKey = pgpSecretKeyRingCollection.getSecretKey(keyID);

        if (pgpSecretKeyKey == null) {
            return null;
        }


        PBESecretKeyDecryptor secretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

        return pgpSecretKeyKey.extractPrivateKey(secretKeyDecryptor);
    }

    //    private static void decrypt(String inputFilepath, String decryptedOutputFilepath, String privateKeyPath, String passphrase)
//            throws IOException, NoSuchProviderException, PGPException {
//        InputStream fileInputStream = new FileInputStream(inputFilepath);
//        OutputStream fileOutputStream = new FileOutputStream(decryptedOutputFilepath);
//        Security.addProvider(new BouncyCastleProvider());
//        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);
//        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(fileInputStream);
//        PGPEncryptedDataList encryptedDataList;
//        Object obj = jcaPGPObjectFactory.nextObject();
//
//        if (obj instanceof PGPEncryptedDataList) {
//            encryptedDataList = (PGPEncryptedDataList) obj;
//        } else {
//            encryptedDataList = (PGPEncryptedDataList) jcaPGPObjectFactory.nextObject();
//        }
//
//        Iterator<PGPPublicKeyEncryptedData> pgpPublicKeyEncryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
//        PGPPrivateKey pgpPrivateKey = null;
//        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;
//
//        while (pgpPrivateKey == null && pgpPublicKeyEncryptedDataIterator.hasNext()) {
//            pgpPublicKeyEncryptedData = pgpPublicKeyEncryptedDataIterator.next();
//            pgpPrivateKey = findSecretKey(new FileInputStream(privateKeyPath), pgpPublicKeyEncryptedData.getKeyID(), passphrase.toCharArray());
//        }
//
//        if (pgpPrivateKey == null) {
//            throw new IllegalArgumentException("Secret key for message not found.");
//        }
//
//        InputStream clear = pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(pgpPrivateKey));
//
//        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
//
//        Object message = plainFact.nextObject();
//
//        if (message instanceof PGPCompressedData) {
//            PGPCompressedData compressedData = (PGPCompressedData) message;
//            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
//
//            message = pgpFact.nextObject();
//        }
//
//        if (message instanceof PGPLiteralData) {
//            PGPLiteralData literalData = (PGPLiteralData) message;
//            InputStream literalDataInputStream = literalData.getInputStream();
//            int ch;
//            while ((ch = literalDataInputStream.read()) >= 0) {
//                fileOutputStream.write(ch);
//            }
//        } else if (message instanceof PGPOnePassSignatureList) {
//            throw new PGPException("Encrypted message contains a signed message - not literal data.");
//        } else {
//            throw new PGPException("Message is not a simple encrypted file - type unknown.");
//        }
//
//        if (pgpPublicKeyEncryptedData.isIntegrityProtected()) {
//            if (!pgpPublicKeyEncryptedData.verify()) {
//                throw new PGPException("Message failed integrity check");
//            }
//        }
//    }

    private static void decrypt(String inputFilepath, String decryptedOutputFilepath, String privateKeyPath, String passphrase)
            throws IOException, NoSuchProviderException, PGPException {
        InputStream fileInputStream = new FileInputStream(inputFilepath);
        OutputStream fileOutputStream = new FileOutputStream(decryptedOutputFilepath);
        Security.addProvider(new BouncyCastleProvider());
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(fileInputStream);
        PGPEncryptedDataList encryptedDataList;
        Object obj = jcaPGPObjectFactory.nextObject();

        if (obj instanceof PGPEncryptedDataList) {
            encryptedDataList = (PGPEncryptedDataList) obj;
        } else {
            encryptedDataList = (PGPEncryptedDataList) jcaPGPObjectFactory.nextObject();
        }

        Iterator<PGPPublicKeyEncryptedData> pgpPublicKeyEncryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
        PGPPrivateKey pgpPrivateKey = null;
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;

        while (pgpPrivateKey == null && pgpPublicKeyEncryptedDataIterator.hasNext()) {
            pgpPublicKeyEncryptedData = pgpPublicKeyEncryptedDataIterator.next();
            pgpPrivateKey = findSecretKey(new FileInputStream(privateKeyPath), pgpPublicKeyEncryptedData.getKeyID(), passphrase.toCharArray());
        }

        if (pgpPrivateKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(pgpPrivateKey));

        int ch;
        while ((ch = clear.read()) >= 0) {
            fileOutputStream.write(ch);
        }

//        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
//
//        Object message = plainFact.nextObject();
//
//        if (message instanceof PGPCompressedData) {
//            PGPCompressedData compressedData = (PGPCompressedData) message;
//            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
//
//            message = pgpFact.nextObject();
//        }
//
//        if (message instanceof PGPLiteralData) {
//            PGPLiteralData literalData = (PGPLiteralData) message;
//            InputStream literalDataInputStream = literalData.getInputStream();
//            int ch;
//            while ((ch = literalDataInputStream.read()) >= 0) {
//                fileOutputStream.write(ch);
//            }
//        } else if (message instanceof PGPOnePassSignatureList) {
//            throw new PGPException("Encrypted message contains a signed message - not literal data.");
//        } else {
//            throw new PGPException("Message is not a simple encrypted file - type unknown.");
//        }
//
//        if (pgpPublicKeyEncryptedData.isIntegrityProtected()) {
//            if (!pgpPublicKeyEncryptedData.verify()) {
//                throw new PGPException("Message failed integrity check");
//            }
//        }
    }

    public static void decryptStream(String inputFilepath, String decryptedOutputFilepath, String privateKeyPath, String passphrase)
            throws IOException, NoSuchProviderException, PGPException {
        InputStream fileInputStream = new FileInputStream(inputFilepath);
        OutputStream fileOutputStream = new FileOutputStream(decryptedOutputFilepath);
        Security.addProvider(new BouncyCastleProvider());
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(fileInputStream);
        PGPEncryptedDataList encryptedDataList;
        Object obj = jcaPGPObjectFactory.nextObject();

        if (obj instanceof PGPEncryptedDataList) {
            encryptedDataList = (PGPEncryptedDataList) obj;
        } else {
            encryptedDataList = (PGPEncryptedDataList) jcaPGPObjectFactory.nextObject();
        }

        Iterator<PGPPublicKeyEncryptedData> pgpPublicKeyEncryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
        PGPPrivateKey pgpPrivateKey = null;
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;

        while (pgpPrivateKey == null && pgpPublicKeyEncryptedDataIterator.hasNext()) {
            pgpPublicKeyEncryptedData = pgpPublicKeyEncryptedDataIterator.next();
            pgpPrivateKey = findSecretKey(new FileInputStream(privateKeyPath), pgpPublicKeyEncryptedData.getKeyID(), passphrase.toCharArray());
        }

        if (pgpPrivateKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(pgpPrivateKey));

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) message;
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());

            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData literalData = (PGPLiteralData) message;
            InputStream literalDataInputStream = literalData.getInputStream();
            int ch;
            while ((ch = literalDataInputStream.read()) >= 0) {
                fileOutputStream.write(ch);
            }
        }
    }

    //    public static void encrypt(String inputFilePath, String encryptedOutputFilepath, String publicKeyPath)
//            throws IOException, PGPException {
//        OutputStream fileOutputStream = new FileOutputStream(encryptedOutputFilepath);
//        fileOutputStream = new ArmoredOutputStream(fileOutputStream);
//        PGPPublicKey pgpPublicKey = readPublicKey(new FileInputStream(publicKeyPath));
//        Security.addProvider(new BouncyCastleProvider());
//
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//
//        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
//                PGPCompressedData.ZIP);
//
//        File inputFile = new File(inputFilePath);
//
//        org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(bOut),
//                PGPLiteralData.BINARY, inputFile);
//
//        compressedDataGenerator.close();
//
//        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setSecureRandom(new SecureRandom()).setProvider("BC");
//
//        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);
//
//        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
//
//        cPk.addMethod(d);
//
//        byte[] bytes = bOut.toByteArray();
//
//        OutputStream cOut = cPk.open(fileOutputStream, bytes.length);
//
//        cOut.write(bytes);
//
//        cOut.close();
//
//        fileOutputStream.close();
//    }


    public static void encrypt(String inputFilePath, String encryptedOutputFilepath, String publicKeyPath)
            throws IOException, PGPException {
        OutputStream fileOutputStream = new FileOutputStream(encryptedOutputFilepath);
        fileOutputStream = new ArmoredOutputStream(fileOutputStream);
        PGPPublicKey pgpPublicKey = readPublicKey(new FileInputStream(publicKeyPath));
        Security.addProvider(new BouncyCastleProvider());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        File inputFile = new File(inputFilePath);

        InputStream inputFileInputStream = new FileInputStream(inputFile);

        int ch;
        while ((ch = inputFileInputStream.read()) >= 0) {
            bOut.write(ch);
        }

        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(fileOutputStream, bytes.length);

        cOut.write(bytes);

        cOut.close();

        fileOutputStream.close();
    }


    public static OutputStream encryptStream (String encryptedOutputFilepath, String publicKeyPath)
            throws IOException, PGPException {
        OutputStream fileOutputStream = new FileOutputStream(encryptedOutputFilepath);
        fileOutputStream = new ArmoredOutputStream(fileOutputStream);
        PGPPublicKey pgpPublicKey = readPublicKey(new FileInputStream(publicKeyPath));
        Security.addProvider(new BouncyCastleProvider());

        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        OutputStream encOut = cPk.open(fileOutputStream, new byte[2048]);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(encOut, // the compressed output stream
                PGPLiteralData.BINARY,
                "iway",  // "filename" to store // length of clear data
                new Date(),  // current time
                new byte[2048]
        );

        return new EncryptedOutputStream(encOut, fileOutputStream, pOut);
    }


    //    public static void main(String[] args) throws Exception {
//        String plainTextFilePath = "testPlainTextFile";
//        String encryptedFilePath = "encryptedFile";
//        String publicKeyFilePath = "testPublic.key";
//        String privateKeyFilePath = "testPrivate.key";
//        String passphrase = "sdksupport2018";
//        String decryptedFilePath = "decryptedFile";
//
//        encrypt(plainTextFilePath, encryptedFilePath, publicKeyFilePath);
//        decrypt(encryptedFilePath, decryptedFilePath, privateKeyFilePath, passphrase);
//
//    }
}

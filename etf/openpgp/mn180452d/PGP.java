package etf.openpgp.mn180452d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PGP
{
    public static StringBuilder decryptionStatus = new StringBuilder();
    public static List<Keys.KeyData> neededKey = null;
    private static byte[] dataToExport = null;

    private static byte[] encrypt(byte[] data, List<Keys.KeyData> receivers, int encryptionType, boolean isFirst, String fileName) throws Exception
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(encryptionType);
        encryptorBuilder.setWithIntegrityPacket(true);
        encryptorBuilder.setSecureRandom(new SecureRandom());

        PGPEncryptedDataGenerator encryptedGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
        for(Keys.KeyData tmpKeyData:receivers)
            encryptedGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(tmpKeyData.keyPair.getPublicKey()));

        OutputStream out =  encryptedGenerator.open(byteOut, new byte[512]);
        if(!isFirst)
        {
            out.write(data);
            out.close();
            encryptedGenerator.close();
            return byteOut.toByteArray();
        }
        PGPLiteralDataGenerator dataGenerator = new PGPLiteralDataGenerator();
        OutputStream  dataGeneratorOut = dataGenerator.open(out, PGPLiteralData.BINARY, fileName, data.length, new Date());

        dataGeneratorOut.write(data);
        dataGeneratorOut.close();
        encryptedGenerator.close();

        return byteOut.toByteArray();
    }

    private static byte[] compress(byte[] data, boolean isFirst, String fileName) throws Exception
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream out =  compressedGenerator.open(byteOut);
        if(!isFirst)
        {
            out.write(data);
            out.close();
            compressedGenerator.close();
            return byteOut.toByteArray();
       }
        PGPLiteralDataGenerator dataGenerator = new PGPLiteralDataGenerator();
        OutputStream  dataGeneratorOut = dataGenerator.open(out, PGPLiteralData.BINARY, fileName, data.length, new Date());

        dataGeneratorOut.write(data);
        dataGeneratorOut.close();
        compressedGenerator.close();

        return byteOut.toByteArray();
    }

    private static byte[] signe(byte[] data, Keys.KeyData sender, String fileName) throws Exception
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        PGPSignatureGenerator signatureGenerator =  new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(sender.keyPair.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, sender.keyPair.getPrivateKey());

        PGPSignatureSubpacketGenerator  signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
        signatureSubpacketGenerator.addSignerUserID(false, sender.keyPair.getPublicKey().getUserIDs().next());
        signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());

        signatureGenerator.generateOnePassVersion(false).encode(byteOut);
        PGPLiteralDataGenerator dataGenerator = new PGPLiteralDataGenerator();
        OutputStream  out = dataGenerator.open(byteOut, PGPLiteralData.BINARY, fileName, data.length, new Date());

        out.write(data);
        signatureGenerator.update(data);

        out.close();
        dataGenerator.close();
        signatureGenerator.generate().encode(byteOut);
        byteOut.close();
        return byteOut.toByteArray();
    }

    public static void PGPEncryptImplementation(String fileName, String saveAsFileName, Keys.KeyData sender, List<Keys.KeyData> receivers, boolean isSigned, boolean isAesUsed, boolean isTDesUsed, boolean isCompressed, boolean isRadix64) throws Exception
    {
        byte[] pureData = Files.readAllBytes(new File(fileName).toPath());

        if(isSigned)
            pureData = signe(pureData, sender, saveAsFileName);
        if(isCompressed)
            pureData = compress(pureData, !isSigned, saveAsFileName);
        if(isAesUsed)
            pureData = encrypt(pureData, receivers, PGPEncryptedData.AES_128, !isSigned && !isCompressed, saveAsFileName);
        else if(isTDesUsed)
            pureData = encrypt(pureData, receivers, PGPEncryptedData.TRIPLE_DES, !isSigned && !isCompressed, saveAsFileName);
        if(isRadix64)
        {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            OutputStream out = new ArmoredOutputStream(byteOut);
            out.write(pureData);
            out.close();
            pureData = byteOut.toByteArray();
            FileWriter writer = new FileWriter(saveAsFileName);
            writer.write(new String(pureData));
            writer.close();
        }
        else
        {
            OutputStream out = new FileOutputStream(saveAsFileName);
            out.write(pureData);
            out.close();
        }
    }

    public static void exportData(String fileName) throws Exception
    {
        OutputStream fileOut = new FileOutputStream(fileName);
        fileOut.write(dataToExport);
        fileOut.close();
    }

    public static void PGPDecryptionImplementation(String fileName) throws Exception
    {
        decryptionStatus.setLength(0);
        neededKey = new ArrayList<>();
        dataToExport = null;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        InputStream fileIn = new FileInputStream(fileName);
        InputStream in = PGPUtil.getDecoderStream(fileIn);
        PGPObjectFactory factory = new JcaPGPObjectFactory(in);

        Object o = factory.nextObject();
        if(o instanceof PGPMarker)
            o = factory.nextObject();

        PGPEncryptedDataList encryptedDataList = null;
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;
        PGPCompressedData compressedData = null;
        PGPOnePassSignature onePassSignature = null;
        PGPLiteralData literalData = null;

        if(o instanceof PGPEncryptedDataList)
        {
            encryptedDataList = (PGPEncryptedDataList) o;
            decryptionStatus.append("Message was encrypted.").append(System.lineSeparator());

            PGPPrivateKey privateKey = null;

            for(PGPEncryptedData encryptedData : encryptedDataList)
                if(encryptedData instanceof PGPPublicKeyEncryptedData)
                {
                    PGPPublicKeyEncryptedData tmpPgpPublicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                    for(Keys.KeyData keyData : Keys.getInstance().getAllKeys())
                        if(keyData.keyPair.getKeyID() == tmpPgpPublicKeyEncryptedData.getKeyID() && keyData.keyPair.getPrivateKey() != null)
                        {
                            pgpPublicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                            neededKey.add(keyData);
                            privateKey = keyData.keyPair.getPrivateKey();
                            break;
                        }
                }
            if(neededKey.size() == 0)
                throw new Exception("Failed to find private key.");
            decryptionStatus.append("Message has integrity check: ").append(pgpPublicKeyEncryptedData.isIntegrityProtected()).append(System.lineSeparator());
            factory = new JcaPGPObjectFactory(pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey)));
            o = factory.nextObject();
        }

        if(o instanceof PGPCompressedData)
        {
            compressedData = (PGPCompressedData) o;
            decryptionStatus.append("Message was compressed.").append(System.lineSeparator());
            factory = new JcaPGPObjectFactory(compressedData.getDataStream());
            o = factory.nextObject();
        }

        if(o instanceof PGPOnePassSignatureList)
        {
            PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) o;
            onePassSignature = onePassSignatureList.get(0);
            decryptionStatus.append("Message has signature.").append(System.lineSeparator());
            Keys.KeyData tmpKeyData = null;
            for(Keys.KeyData keyData : Keys.getInstance().getAllKeys())
                if(keyData.keyPair.getKeyID() == onePassSignature.getKeyID())
                {
                    tmpKeyData = keyData;
                    break;
                }
            if(tmpKeyData != null)
            {
                onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), tmpKeyData.keyPair.getPublicKey());
                decryptionStatus.append("Signed by ").append(tmpKeyData.userId).append(System.lineSeparator());
            }
            else
            {
                decryptionStatus.append("Failed to find public key for signature.").append(System.lineSeparator());
                onePassSignature = null;
            }
            o = factory.nextObject();
        }

        if(o instanceof PGPLiteralData)
        {
            literalData = (PGPLiteralData) o;
            in = literalData.getInputStream();

            int len = 0;
            byte[] buf = new byte[512];
            while ((len = in.read(buf, 0, buf.length)) >= 0)
            {
                if (onePassSignature != null)
                    onePassSignature.update(buf, 0, len);
                byteOut.write(buf, 0, len);
            }
        }

        if (onePassSignature != null)
        {
            PGPSignatureList signaturesConfirmationList = (PGPSignatureList) factory.nextObject();
            PGPSignature signature = signaturesConfirmationList.get(0);
            decryptionStatus.append("Message signature check: ").append(onePassSignature.verify(signature)).append(System.lineSeparator());
        }

        if(pgpPublicKeyEncryptedData != null && pgpPublicKeyEncryptedData.isIntegrityProtected())
            decryptionStatus.append("Message integrity check: ").append(pgpPublicKeyEncryptedData.verify()).append(System.lineSeparator());

        byteOut.close();
        in.close();
        fileIn.close();

        dataToExport = byteOut.toByteArray();
    }
}

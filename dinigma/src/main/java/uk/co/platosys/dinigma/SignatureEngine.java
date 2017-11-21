
        package uk.co.platosys.dinigma;



        import java.io.ByteArrayInputStream;
        import java.io.ByteArrayOutputStream;
        import java.io.InputStream;
        import java.util.ArrayList;
        import java.util.Date;
        import java.util.List;
        import org.bouncycastle.jce.provider.BouncyCastleProvider;
        import org.bouncycastle.openpgp.PGPCompressedData;
        import org.bouncycastle.openpgp.PGPObjectFactory;
        import org.bouncycastle.openpgp.PGPPrivateKey;
        import org.bouncycastle.openpgp.PGPPublicKey;
        import org.bouncycastle.openpgp.PGPSecretKey;
        import org.bouncycastle.openpgp.PGPSignature;
        import org.bouncycastle.openpgp.PGPSignatureGenerator;
        import org.bouncycastle.openpgp.PGPSignatureList;
        import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
        import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
        import org.bouncycastle.openpgp.PGPUtil;
        import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
        import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
        import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
        import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
        import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
        import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
        import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
        import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
        import uk.co.platosys.dinigma.Key;
        import uk.co.platosys.dinigma.Lock;
        import uk.co.platosys.dinigma.Minigma;
        import uk.co.platosys.dinigma.exceptions.MinigmaException;
        import uk.co.platosys.dinigma.utils.Kidney;
        import uk.co.platosys.dinigma.utils.MinigmaUtils;


/**
 *
 * @author edward
 */
public class SignatureEngine {
    private static String TAG ="SignatureEngine";



    public static String sign(String string, Key key, char [] passphrase) throws MinigmaException{
        byte[] bytes = MinigmaUtils.toByteArray(string);
        return sign(bytes, key, passphrase);
    }
    static String sign(byte [] bytes, Key key, char[] passphrase) throws MinigmaException{
        try{
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
            PGPSignature signature = signatureGenerator.generate();
            signature.update(bytes, 0, 0);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            signature.encode(bos);
            byte [] sigBytes = bos.toByteArray();
            return MinigmaUtils.encode(sigBytes);
        }catch(Exception e){

            throw new MinigmaException("error making signature", e);
        }
    }

    public static List<List<Long>> verify(String string, String signatureValue, Lock lock){
        return verify(MinigmaUtils.toByteArray(string), signatureValue, lock);
    }
    static List <List<Long>> verify(byte [] bytes, String signatureValue, Lock lock){
        List<Long> signors = new ArrayList<Long>();
        List<Long> nonsignors=new ArrayList<Long>();
        List<List<Long>> results = new ArrayList<List<Long>>();
        results.add(signors);
        results.add(nonsignors);
        try{
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            byte [] sigVal = MinigmaUtils.decode(signatureValue);
            //Log.d(TAG,"sigVal  = "+Kidney.toString(sigVal));
            ByteArrayInputStream bis = new ByteArrayInputStream(sigVal);
            InputStream in = PGPUtil.getDecoderStream(bis);
            PGPObjectFactory    pgpFactory = new PGPObjectFactory(in, calculator );
            PGPSignatureList    signatureList = null;
            Object    o = pgpFactory.nextObject();
            if (o instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData)o;
                pgpFactory = new PGPObjectFactory(compressedData.getDataStream(), calculator);
                signatureList = (PGPSignatureList)pgpFactory.nextObject();
            }else{
                signatureList = (PGPSignatureList)o;
            }
            //Log.d(TAG,5, "signatureList has "+signatureList.size()+" signatures");

            for(int i=0; i<signatureList.size(); i++){
                PGPSignature signature = signatureList.get(i);
                long keyID = signature.getKeyID();
                PGPPublicKey publicKey = lock.getPublicKey(keyID);
                PGPContentVerifierBuilderProvider pgpContentVerifierBuilder = new JcaPGPContentVerifierBuilderProvider();//.get(keyAlgorithm, Minigma.HASH_ALGORITHM);
                signature.init(pgpContentVerifierBuilder, publicKey);
                signature.update(bytes, 0,0);
                if(signature.verify()){

                    signors.add(keyID);
                }else{
                    nonsignors.add(keyID);

                }
            }
        }catch(Exception x){
//TODO Yeah? and what about it?
        }
        return results;
    }

    public static PGPSignature getKeyCertification(Key key, char[] passphrase, PGPPublicKey keyToBeSigned){

        try{
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeSigned);
            return signature;
        }catch(Exception x){
            return null;
        }
    }

    static PGPSignature getKeyRevocation(Key key, char [] passphrase, PGPPublicKey keyToBeRevoked){

        try{
            PGPSecretKey secretKey = key.getSigningKey();
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);

            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.DIRECT_KEY,privateKey);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeRevoked);
            return signature;
        }catch(Exception x){
            return null;
        }
    }
}
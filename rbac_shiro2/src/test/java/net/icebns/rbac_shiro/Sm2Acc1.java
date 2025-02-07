package net.icebns.rbac_shiro;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

// 简单累加器类
class SimpleAccumulator {
    private BigInteger accumulator;
    private final BigInteger modulus;

    public SimpleAccumulator(BigInteger initialValue, BigInteger modulus) {
        this.accumulator = initialValue;
        this.modulus = modulus;
    }

    public void add(BigInteger element) {
        accumulator = accumulator.multiply(element).mod(modulus);
    }

    public BigInteger getAccumulatorValue() {
        return accumulator;
    }

    // 验证元素是否在累加器中（需保存所有元素的乘积）
    public boolean verify(BigInteger element, BigInteger productWithoutElement) {
        BigInteger expected = productWithoutElement.multiply(element).mod(modulus);
        return expected.equals(accumulator);
    }
}

public class Sm2Acc1 {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 密钥对文件路径
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";

    // 生成或加载 SM2 密钥对
    public static KeyPair generateOrLoadSM2KeyPair() throws Exception {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            // 从文件中加载密钥对
            try (ObjectInputStream privateKeyIn = new ObjectInputStream(new FileInputStream(privateKeyFile));
                 ObjectInputStream publicKeyIn = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
                PrivateKey privateKey = (PrivateKey) privateKeyIn.readObject();
                PublicKey publicKey = (PublicKey) publicKeyIn.readObject();
                return new KeyPair(publicKey, privateKey);
            }
        } else {
            // 生成新的密钥对
            KeyPair keyPair = generateSM2KeyPair();
            // 保存密钥对到文件
            try (ObjectOutputStream privateKeyOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
                 ObjectOutputStream publicKeyOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
                privateKeyOut.writeObject(keyPair.getPrivate());
                publicKeyOut.writeObject(keyPair.getPublic());
            }
            return keyPair;
        }
    }

    // 生成 SM2 密钥对
    public static KeyPair generateSM2KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));
        return keyPairGenerator.generateKeyPair();
    }

    // 使用 SM2 算法加密数据
    public static byte[] encryptData(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        // 设置固定的随机数
        SecureRandom fixedRandom = new SecureRandom(new byte[0]);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, fixedRandom);
        return cipher.doFinal(data);
    }

    // 使用 SM2 算法解密数据
    public static byte[] decryptData(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static class SM2DynamicAccumulator {
        private final X9ECParameters sm2Parameters = GMNamedCurves.getByName("sm2p256v1");
        private final ECDomainParameters domainParameters = new ECDomainParameters(
                sm2Parameters.getCurve(),
                sm2Parameters.getG(),
                sm2Parameters.getN(),
                sm2Parameters.getH()
        );
        private ECPoint accumulator;
        private List<byte[]> encryptedElements;
        private SimpleAccumulator simpleAccumulator;
        //0的位数决定见证值长度
        private final BigInteger modulus = new BigInteger("1000000000000000000000007"); // 自定义模数

        public SM2DynamicAccumulator() {
            this.accumulator = sm2Parameters.getCurve().getInfinity();
            this.encryptedElements = new ArrayList<>();
            this.simpleAccumulator = new SimpleAccumulator(BigInteger.ONE, modulus);
        }

        public void addElement(PublicKey publicKey, BigInteger element) throws Exception {
            byte[] encryptedElement = encryptData(publicKey, element.toByteArray());
            encryptedElements.add(encryptedElement);
            ECPoint point = domainParameters.getG().multiply(element);
            accumulator = accumulator.add(point);

            // 使用 SimpleAccumulator 进行累加
            BigInteger encryptedElementBigInt = new BigInteger(1, encryptedElement);
            simpleAccumulator.add(encryptedElementBigInt);
        }

        public boolean verifyMembership(BigInteger element, ECPoint witness) {
            ECPoint point = domainParameters.getG().multiply(element);
            ECPoint result = witness.add(point);
            return result.equals(accumulator);
        }

        public ECPoint getAccumulator() {
            return accumulator;
        }

        public BigInteger getWitnessValue() {
            return simpleAccumulator.getAccumulatorValue();
        }

        // 新增公共方法，用于返回 domainParameters
        public ECDomainParameters getDomainParameters() {
            return domainParameters;
        }
    }

    // 新增方法：生成并返回 SM2 密钥对
    public static KeyPair generateNewSM2KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateSM2KeyPair();
    }

    public static void main(String[] args) throws Exception {
        // 生成新的 SM2 密钥对
        KeyPair keyPair = generateNewSM2KeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);

        // 初始化动态累加器
        SM2DynamicAccumulator accumulator = new SM2DynamicAccumulator();

        // 模拟需要累加的元素，支持汉字和字母
        List<String> inputElements = new ArrayList<>();
        inputElements.add("123");
        inputElements.add("abc");
        inputElements.add("你好");

        List<BigInteger> elements = new ArrayList<>();
        for (String input : inputElements) {
            BigInteger element = new BigInteger(input.getBytes());
            elements.add(element);
        }

        System.out.println("Element: " + elements);
        // 添加元素到累加器
        for (BigInteger element : elements) {
            accumulator.addElement(publicKey, element);
        }

        // 生成见证值
        BigInteger witnessValue = accumulator.getWitnessValue();
        System.out.println("Witness Value: " + witnessValue.toString());

        // 模拟见证值存储，实际应用中可存储到数据库等
        System.out.println("Witness Value stored for authentication.");

        // 验证元素成员资格
        BigInteger testElement = elements.get(0);
        // 通过 accumulator 实例获取 domainParameters
        ECDomainParameters domainParams = accumulator.getDomainParameters();
        ECPoint witness = accumulator.getAccumulator().subtract(domainParams.getG().multiply(testElement));
        boolean isMember = accumulator.verifyMembership(testElement, witness);
        System.out.println("Element " + testElement + " is a member: " + isMember);

        // 解密过程
        System.out.println("\nDecryption process:");
        for (byte[] encryptedElement : accumulator.encryptedElements) {
            byte[] decryptedElement = decryptData(privateKey, encryptedElement);
            String originalElement = new String(decryptedElement);
            System.out.println("Decrypted Element: " + originalElement);
        }
    }
}
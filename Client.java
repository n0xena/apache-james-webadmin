package de.cryptearth.crypto.pki;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import javax.net.ssl.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.*;
public final class Client
{
    public static void main(final String... args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom secureRandom=SecureRandom.getInstance("DRBG");
        secureRandom.setSeed(SecureRandom.getInstanceStrong().generateSeed(256));
        X509Certificate rootCertificate=(new JcaX509CertificateConverter()).getCertificate((X509CertificateHolder)(new PEMParser(new FileReader("root.crt"))).readObject());
        X509Certificate clientCertificate=(new JcaX509CertificateConverter()).getCertificate((X509CertificateHolder)(new PEMParser(new FileReader("client.crt"))).readObject());
        KeyPair clientKeyPair=(new JcaPEMKeyConverter()).getKeyPair((PEMKeyPair)(new PEMParser(new FileReader("client.key"))).readObject());

        KeyStore keyManagerStore=KeyStore.getInstance(KeyStore.getDefaultType());
        keyManagerStore.load(null, null);
        keyManagerStore.setKeyEntry("client", clientKeyPair.getPrivate(), "client".toCharArray(), new java.security.cert.Certificate[] {clientCertificate});
        KeyManagerFactory keyManagerFactory=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyManagerStore, "client".toCharArray());
        KeyStore trustManagerStore=KeyStore.getInstance(KeyStore.getDefaultType());
        trustManagerStore.load(null, null);
        trustManagerStore.setCertificateEntry("root", rootCertificate);
        TrustManagerFactory trustManagerFactory=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustManagerStore);
        SSLContext sslContext=SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), secureRandom);

        SSLSocketFactory sslSocketFactory=sslContext.getSocketFactory();
        SSLSocket sslSocket=(SSLSocket)sslSocketFactory.createSocket("127.0.0.1", 8888);
        sslSocket.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"});
        sslSocket.setEnabledProtocols(new String[] {"TLSv1.2"});
        sslSocket.setNeedClientAuth(true);
        sslSocket.setUseClientMode(true);
        sslSocket.startHandshake();

        DataInputStream input=new DataInputStream(sslSocket.getInputStream());
        System.out.println(input.readUTF());
        DataOutputStream output=new DataOutputStream(sslSocket.getOutputStream());
        output.writeUTF("Hello Client");
        output.flush();

        input.close();
        output.close();
        sslSocket.close();
    }
}

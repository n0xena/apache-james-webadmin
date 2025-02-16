package de.cryptearth.crypto.pki;
import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.x500.style.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.*;
public final class Main
{
	private static BigInteger serial=BigInteger.ONE;
	private static Date now=new Date(System.currentTimeMillis());
	private static SecureRandom secureRandom;
	private static KeyPairGenerator keyPairGenerator;
	private static KeyPair rootKeyPair;
	private static X509Certificate rootX509Certificate;
	public final static void main(final String... args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		secureRandom=SecureRandom.getInstance("DRBG");
		secureRandom.setSeed(SecureRandom.getInstanceStrong().generateSeed(256));
		keyPairGenerator=KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096, secureRandom);
		createRoot();
		createLeaf();
	}
	private final static void createRoot() throws Exception
	{
		rootKeyPair=keyPairGenerator.generateKeyPair();
		X500Name x500Name=(new X500NameBuilder())
			.addRDN(BCStyle.CN, "root")
			.build();
		X509v3CertificateBuilder x509v3CertificateBuilder=new JcaX509v3CertificateBuilder(x500Name, serial, now, new Date(now.getTime()+31536000000L), x500Name, rootKeyPair.getPublic())
			.addExtension(Extension.create(Extension.basicConstraints, true, new BasicConstraints(true)))
			.addExtension(Extension.create(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)));
		ContentSigner contentSigner=(new JcaContentSignerBuilder("SHA256withRSA"))
			.build(rootKeyPair.getPrivate());
		X509CertificateHolder x509CertificateHolder=x509v3CertificateBuilder.build(contentSigner);
		rootX509Certificate=(new JcaX509CertificateConverter()).getCertificate(x509CertificateHolder);
		Writer writer=new FileWriter("root.key");
		JcaPEMWriter jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(rootKeyPair);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
		writer=new FileWriter("root.crt");
		jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(rootX509Certificate);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
	}
	private final static void createLeaf() throws Exception
	{
		KeyPair serverKeyPair=keyPairGenerator.generateKeyPair();
		serial=serial.add(BigInteger.ONE);
		X500Name serverX500Name=(new X500NameBuilder())
			.addRDN(BCStyle.CN, "server")
			.build();
		X509v3CertificateBuilder serverX509v3CertificateBuilder=new JcaX509v3CertificateBuilder(rootX509Certificate, serial, now, new Date(now.getTime()+31536000000L), serverX500Name, serverKeyPair.getPublic())
			.addExtension(Extension.create(Extension.basicConstraints, true, new BasicConstraints(false)))
			.addExtension(Extension.create(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyAgreement|KeyUsage.digitalSignature)))
			.addExtension(Extension.create(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)));
		ContentSigner contentSigner=(new JcaContentSignerBuilder("SHA256withRSA"))
			.build(rootKeyPair.getPrivate());
		X509CertificateHolder serverX509CertificateHolder=serverX509v3CertificateBuilder.build(contentSigner);
		X509Certificate serverX509Certificate=(new JcaX509CertificateConverter()).getCertificate(serverX509CertificateHolder);
		Writer writer=new FileWriter("server.key");
		JcaPEMWriter jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(serverKeyPair);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
		writer=new FileWriter("server.crt");
		jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(serverX509Certificate);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();

		KeyPair clientKeyPair=keyPairGenerator.generateKeyPair();
		serial=serial.add(BigInteger.ONE);
		X500Name clientX500Name=(new X500NameBuilder())
			.addRDN(BCStyle.CN, "client")
			.build();
		X509v3CertificateBuilder clientX509v3CertificateBuilder=new JcaX509v3CertificateBuilder(rootX509Certificate, serial, now, new Date(now.getTime()+31536000000L), clientX500Name, clientKeyPair.getPublic())
			.addExtension(Extension.create(Extension.basicConstraints, true, new BasicConstraints(false)))
			.addExtension(Extension.create(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyAgreement|KeyUsage.digitalSignature)))
			.addExtension(Extension.create(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)));
		contentSigner=(new JcaContentSignerBuilder("SHA256withRSA"))
			.build(rootKeyPair.getPrivate());
		X509CertificateHolder clientX509CertificateHolder=clientX509v3CertificateBuilder.build(contentSigner);
		X509Certificate clientX509Certificate=(new JcaX509CertificateConverter()).getCertificate(clientX509CertificateHolder);
		writer=new FileWriter("client.key");
		jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(clientKeyPair);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
		writer=new FileWriter("client.crt");
		jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(clientX509Certificate);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
	}
}

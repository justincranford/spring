package com.github.justincranford.spring.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class PkiUtil {
	public static final SecureRandom SECURE_DEFAULT = new SecureRandom();

	record CertChainKey(Certificate[] certChain, PrivateKey key) {}

//	final String certPem = toPem("CERTIFICATE", cert.getEncoded());
//	final String keyPem  = toPem("PRIVATE KEY", cert.getEncoded());

//	final KeyStore keyStore = KeyStore.getInstance("PKCS12", Security.getProvider("SunJSSE"));
//	keyStore.load(null, null);
//	keyStore.setKeyEntry("ca", keyPair.getPrivate(), "ca".toCharArray(), new Certificate[] {cert});

	public static KeyStore.PrivateKeyEntry createTlsServer() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", Security.getProvider("SunRsaSign"));
		keyPairGenerator.initialize(2048, SECURE_DEFAULT);

		final KeyPair caKeyPair = keyPairGenerator.generateKeyPair();
		final Certificate caCert = createCert(
			Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
			Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
			new BigInteger(159, SECURE_DEFAULT),
			caKeyPair.getPublic(),
			new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
			caKeyPair.getPrivate(),
			new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
			"SHA256withRSA",
			Security.getProvider("SunRsaSign"),
			new Extensions(new Extension[] {
				new Extension(Extension.basicConstraints, true, new BasicConstraints(0)           .toASN1Primitive().getEncoded()),
				new Extension(Extension.keyUsage,         true, new KeyUsage(KeyUsage.keyCertSign).toASN1Primitive().getEncoded())
			})
		);

		final KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
		final Certificate serverCert = createCert(
			Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
			Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
			new BigInteger(159, SECURE_DEFAULT),
			serverKeyPair.getPublic(),
			new X500Name(RFC4519Style.INSTANCE, "CN=server,DC=example.com"),
			caKeyPair.getPrivate(),
			new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
			"SHA256withRSA",
			Security.getProvider("SunRsaSign"),
			new Extensions(new Extension[] {
				new Extension(Extension.keyUsage,         true,  new KeyUsage(KeyUsage.digitalSignature)            .toASN1Primitive().getEncoded()),
				new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded())
			})
		);

		return new KeyStore.PrivateKeyEntry(serverKeyPair.getPrivate(), new Certificate[] {serverCert, caCert});
	}

	public static X509Certificate createCert(
		final Date       notBefore,
		final Date       notAfter,
		final BigInteger serialNumber,
		final PublicKey  subjectPublicKey,
		final X500Name   subjectDN,
		final PrivateKey issuerPrivateKey,
		final X500Name   issuerDN,
		final String     issuerSigningAlgorithm,
		final Provider   issuerSigningProvider,
		final Extensions extensions
	) throws Exception {
		final JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, subjectPublicKey);
		for (final ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
			jcaX509v3CertificateBuilder.addExtension(extensions.getExtension(oid));
		}
		final JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(issuerSigningAlgorithm);
		if (issuerSigningProvider != null) {
			jcaContentSignerBuilder.setProvider(issuerSigningProvider);
		}
		final ContentSigner contentSigner = jcaContentSignerBuilder.build(issuerPrivateKey);
		X509CertificateHolder x509CertificateHolder = jcaX509v3CertificateBuilder.build(contentSigner);
		final JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
		return jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
	}

	public static String toPem(final String type, final byte[]... payloads) {
        final Encoder mimeEncoder = Base64.getMimeEncoder(64, "\n".getBytes());
		final StringBuilder sb = new StringBuilder();
		for (final byte[] payload : payloads) {
			sb.append("-----BEGIN ").append(type).append("-----\n");
			sb.append(mimeEncoder.encodeToString(payload));
			sb.append("\n-----END ").append(type).append("-----\n");
        }
		return sb.toString();
	}
}

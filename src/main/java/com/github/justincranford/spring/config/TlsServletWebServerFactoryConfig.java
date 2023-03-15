package com.github.justincranford.spring.config;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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
import java.util.List;
import java.util.stream.Stream;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TlsServletWebServerFactoryConfig {
	@Value(value="${server.port}")
    protected int serverPort;

	// Same method signature as ServletWebServerFactoryConfiguration$EmbeddedTomcat
	@Bean
	public ServletWebServerFactory servletWebServerFactory(
			final ObjectProvider<TomcatConnectorCustomizer> connectorCustomizers,
			final ObjectProvider<TomcatContextCustomizer> contextCustomizers,
			final ObjectProvider<TomcatProtocolHandlerCustomizer<?>> protocolHandlerCustomizers
	) throws Exception {
		// start Tomcat with TLS; clobbers all ${server.ssl.*} settings
		final TomcatServletWebServerFactory factory = new TlsServletWebServerFactory();
		factory.getTomcatConnectorCustomizers().addAll(connectorCustomizers.orderedStream().toList());
		factory.getTomcatContextCustomizers().addAll(contextCustomizers.orderedStream().toList());
		factory.getTomcatProtocolHandlerCustomizers().addAll(protocolHandlerCustomizers.orderedStream().toList());

		// add redirect from "http://${server.address}:80" to "https://${server.address}:${server.port}"
    	factory.addAdditionalTomcatConnectors(this.createRedirectConnector());

    	// add Tomcat life cycle listener to log life cycle events
    	factory.setContextLifecycleListeners(Stream.concat(factory.getContextLifecycleListeners().stream(), List.of(new MyLifecycleLogger()).stream()).toList());

    	return factory;
	}

	public static class TlsServletWebServerFactory extends TomcatServletWebServerFactory {
		private Logger logger = LoggerFactory.getLogger(TlsServletWebServerFactory.class);

		// Mozilla recommended ciphers (January 2023)
		private static final List<String> PROTOCOLS_TLS13 = List.of("TLSv1.3");
		private static final List<String> PROTOCOLS_TLS12 = List.of("TLSv1.2");
		private static final List<String> PROTOCOLS_TLS13_TLS12 = Stream.concat(PROTOCOLS_TLS13.stream(), PROTOCOLS_TLS12.stream()).toList();
		private static final List<String> CIPHERS_TLS13 = List.of("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256");
		private static final List<String> CIPHERS_TLS12 = List.of("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256");
		private static final List<String> CIPHERS_TLS13_TLS12 = Stream.concat(CIPHERS_TLS13.stream(), CIPHERS_TLS12.stream()).toList();

		@Override
	    protected void postProcessContext(final Context servletContext) {
	        final SecurityCollection webResourceCollection = new SecurityCollection();
	        webResourceCollection.addPattern("/*");
	        final SecurityConstraint securityConstraint = new SecurityConstraint();
	        securityConstraint.addCollection(webResourceCollection);
	        securityConstraint.setUserConstraint("CONFIDENTIAL");	// "NONE", "INTEGRAL", or "CONFIDENTIAL"
	        servletContext.addConstraint(securityConstraint);
	    }

		@Override
		public void customizeConnector(final Connector connector) {
			try {
				final Ssl ssl = new Ssl();
				ssl.setEnabled(true);
				ssl.setProtocol("TLSv1.3");
				ssl.setClientAuth(ClientAuth.WANT);
				ssl.setEnabledProtocols(PROTOCOLS_TLS13_TLS12.toArray(new String[0]));
				ssl.setCiphers(CIPHERS_TLS13_TLS12.toArray(new String[0]));

				final KeyStore.PrivateKeyEntry server = createTlsServer();
				final String serverPrivateKeyPem = toPem("RSA PRIVATE KEY", PrivateKeyInfo.getInstance(server.getPrivateKey().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
				final String serverCertChainPem  = toPem("CERTIFICATE",     server.getCertificateChain()[0].getEncoded());
				final String caCertChainPem      = toPem("CERTIFICATE",     server.getCertificateChain()[1].getEncoded());

//				final KeyStoreManager ca     = this.createCa    (null, "RSA", "DC=CA",     "CaPwd".toCharArray());
//				final KeyStoreManager server = this.createServer(ca,   "RSA", "CN=Server", "ServerPwd".toCharArray());
////			final KeyStoreManager client = this.createClient(ca,   "RSA", "CN=Client", "ClientPwd".toCharArray());
//				final String caCertChainPem      = PemUtil.toString("CERTIFICATE",     ca.entry().getCertificateChain()[0].getEncoded());
//				final String serverCertChainPem  = PemUtil.toString("CERTIFICATE",     server.entry().getCertificateChain()[0].getEncoded());
//				final String serverPrivateKeyPem = PemUtil.toString("RSA PRIVATE KEY", PrivateKeyInfo.getInstance(server.entry().getPrivateKey().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
////			final String serverPrivateKeyPem = PemUtil.toString("RSA PRIVATE KEY", server.entry().getPrivateKey().getEncoded());
////			final String clientCertChainPem  = PemUtil.toString("CERTIFICATE",     client.entry().getCertificateChain()[0].getEncoded());
////			final String clientPrivateKeyPem = PemUtil.toString("RSA PRIVATE KEY", PrivateKeyInfo.getInstance(client.entry().getPrivateKey().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
//////			final String clientPrivateKeyPem = PemUtil.toString("RSA PRIVATE KEY", client.entry().getPrivateKey().getEncoded());
				this.logger.info("CA certificate chain:\n{}\n",     caCertChainPem);
				this.logger.info("Server certificate chain:\n{}\n", serverCertChainPem);
				this.logger.info("Server private key:\n{}\n",       serverPrivateKeyPem);
////			this.logger.info("Client certificate chain:\n{}\n", clientCertChainPem);
////			this.logger.info("Client private key:\n{}\n",       clientPrivateKeyPem);
				final Path caCertificateChainPath     = Files.writeString(Files.createTempFile("ca",     ".crt"), caCertChainPem,      StandardOpenOption.CREATE);
				final Path serverCertificateChainPath = Files.writeString(Files.createTempFile("server", ".crt"), serverCertChainPem,  StandardOpenOption.CREATE);
				final Path serverPrivateKeyPath       = Files.writeString(Files.createTempFile("server", ".p8"),  serverPrivateKeyPem, StandardOpenOption.CREATE);
////			final Path clientCertificateChainPath = Files.writeString(Files.createTempFile("client", ".crt"), clientCertChainPem,  StandardOpenOption.CREATE);
////			final Path clientPrivateKeyPath       = Files.writeString(Files.createTempFile("client", ".p8"),  clientPrivateKeyPem, StandardOpenOption.CREATE);
				ssl.setTrustCertificate(caCertificateChainPath.toFile().toString());
				ssl.setCertificate(serverCertificateChainPath.toFile().toString());
				ssl.setCertificatePrivateKey(serverPrivateKeyPath.toFile().toString());
				this.setSsl(ssl);
			} catch(Exception e) {
				throw new RuntimeException("Cert creation failed during Tomcat TLS customization", e);
			}
			super.customizeConnector(connector);
		}

//		private KeyStoreManager createCa(final KeyStoreManager issuer, String keyPairAlg, String rdn, final char[] password) throws Exception {
//			Extension bc = new Extension(Extension.basicConstraints, true, new BasicConstraints(0)           .toASN1Primitive().getEncoded());
//			Extension ku = new Extension(Extension.keyUsage,         true, new KeyUsage(KeyUsage.keyCertSign).toASN1Primitive().getEncoded());
//			final Extensions extensions = new Extensions(new Extension[] {bc, ku});
//			return KeyStoreManager.create(issuer, rdn, keyPairAlg, password, password, extensions, null);
//		}
//
//		private KeyStoreManager createServer(final KeyStoreManager issuer, String keyPairAlg, String rdn, final char[] password) throws Exception {
//			final Map<Integer, String> san = Map.of(GeneralName.dNSName, "localhost", GeneralName.iPAddress, "127.0.0.1");
//			final Extensions extensions = ExtensionUtil.extensions(ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_SERVER, ExtensionUtil.sanExtension(san));
//			return KeyStoreManager.create(issuer, rdn, keyPairAlg, password, password, extensions, null);
//		}
//
//		private KeyStoreManager createClient(final KeyStoreManager issuer, String keyPairAlg, String subjectRDN, final char[] password) throws Exception {
//			final Map<Integer, String> san = Map.of(GeneralName.rfc822Name, "client1@example.com");
//			final Extensions extensions = ExtensionUtil.extensions(ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_CLIENT, ExtensionUtil.sanExtension(san));
//			return KeyStoreManager.create(issuer, "CN=client+serialNumber=1", "RSA", password, password, extensions, null);
//		}
	}

	private Connector createRedirectConnector() {
	    final Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);	// Http11NioProtocol
	    connector.setRejectSuspiciousURIs(true);
	    connector.setSecure(false);
	    connector.setScheme("http");
	    connector.setPort(80);
	    connector.setRedirectPort(this.serverPort);
		connector.setProperty("bindOnInit", "false");
	    return connector;
	}

    private static class MyLifecycleLogger implements LifecycleListener {
    	private Logger logger = LoggerFactory.getLogger(MyLifecycleLogger.class);
    	@Override
		public void lifecycleEvent(final LifecycleEvent lifecycleEvent) {
			this.logger.info("type={}", lifecycleEvent.getType());
		}
	}

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

package com.github.justincranford.spring.util.config;

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
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

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
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.github.justincranford.spring.util.config.TlsConfig.TlsSettings.TlsAutoConfig;

@Configuration
@EnableWebSecurity
public class TlsConfig {
    private Logger logger = LoggerFactory.getLogger(TlsConfig.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final AtomicInteger HTTP_PORT = new AtomicInteger(80);

    @Bean
    public ServletWebServerFactory servletWebServerFactory(
        final ObjectProvider<TomcatConnectorCustomizer>          connectorCustomizers,
        final ObjectProvider<TomcatContextCustomizer>            contextCustomizers,
        final ObjectProvider<TomcatProtocolHandlerCustomizer<?>> protocolHandlerCustomizers,
        final TlsSettings                                        tlsSettings,
        final TlsGeneratedConfig                                 tlsGeneratedConfig
    ) throws Exception {
        // use ${server.ssl.*} settings to start Tomcat with auto-generated TLS server PEM files
        final TomcatServletWebServerFactory factory = new TlsTomcatServletWebServerFactory(tlsSettings, tlsGeneratedConfig);

        // Same internal steps as ServletWebServerFactoryConfiguration$EmbeddedTomcat
        factory.getTomcatConnectorCustomizers().addAll(connectorCustomizers.orderedStream().toList());
        factory.getTomcatContextCustomizers().addAll(contextCustomizers.orderedStream().toList());
        factory.getTomcatProtocolHandlerCustomizers().addAll(protocolHandlerCustomizers.orderedStream().toList());

        // add "http://${server.address}:80" listener to redirect to "https://${server.address}:${server.port}"
        if (tlsSettings.serverSslEnabled() || tlsSettings.tlsAutoConfig().enabled()) {
            factory.addAdditionalTomcatConnectors(this.createHttpToHttpsRedirectConnector(tlsSettings));
        }

        // add life cycle listener to log all Tomcat life cycle events
        factory.setContextLifecycleListeners(Stream.concat(factory.getContextLifecycleListeners().stream(), List.of(new MyLifecycleLogger()).stream()).toList());

        return factory;
    }

    // create ${server.ssl.*} settings to start Tomcat with auto-generated TLS server PEM files
    private class TlsTomcatServletWebServerFactory extends TomcatServletWebServerFactory {
        // Mozilla recommended "intermediate" ciphersuites (January 2023)
        private static final List<String> PROTOCOLS_TLS13_ONLY = List.of("TLSv1.3");
        private static final List<String> PROTOCOLS_TLS12_ONLY = List.of("TLSv1.2");
        private static final List<String> PROTOCOLS_TLS13_TLS12 = Stream.concat(PROTOCOLS_TLS13_ONLY.stream(), PROTOCOLS_TLS12_ONLY.stream()).toList();
        private static final List<String> CIPHERS_TLS13_ONLY = List.of("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256");
        private static final List<String> CIPHERS_TLS12_ONLY = List.of("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256");
        private static final List<String> CIPHERS_TLS13_TLS12 = Stream.concat(CIPHERS_TLS13_ONLY.stream(), CIPHERS_TLS12_ONLY.stream()).toList();
        

        private final TlsSettings tlsSettings;
        private final TlsGeneratedConfig tlsGeneratedConfig;
        public TlsTomcatServletWebServerFactory(final TlsSettings tlsSettings, final TlsGeneratedConfig tlsGeneratedConfig) {
        	this.tlsSettings = tlsSettings;
        	this.tlsGeneratedConfig = tlsGeneratedConfig;
        }

        @Override
        protected void postProcessContext(final Context servletContext) {
            if (this.tlsSettings.serverSslEnabled() || this.tlsSettings.tlsAutoConfig().enabled()) {
                final SecurityCollection webResourceCollection = new SecurityCollection();
                webResourceCollection.addPattern("/*");
                final SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.addCollection(webResourceCollection);
                securityConstraint.setUserConstraint("CONFIDENTIAL");	// "NONE", "INTEGRAL", or "CONFIDENTIAL"
                servletContext.addConstraint(securityConstraint);
            }
        }

        @Override
        public void customizeConnector(final Connector connector) {
        	if (this.tlsSettings.tlsAutoConfig().enabled()) {
        		final Path caCertificatePath;
        		final Path serverCertificatePath;
        		final Path serverPrivateKeyPath;
            	try {
                    // Encode server privateKey, server cert, and root CA cert as PEM
                    final String caCertPem           = toPem("CERTIFICATE",     this.tlsGeneratedConfig.x509CaCertificate().getEncoded());
                    final String serverCertPem       = toPem("CERTIFICATE",     this.tlsGeneratedConfig.x509ServerCertificate().getEncoded());
					final String serverPrivateKeyPem = toPem(this.tlsGeneratedConfig.serverPrivateKey().getAlgorithm().toUpperCase() + " PRIVATE KEY", PrivateKeyInfo.getInstance(this.tlsGeneratedConfig.serverPrivateKey().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());

                    // Log server privateKey, server cert, and root CA cert as PEM
                    TlsConfig.this.logger.info("CA certificate chain:\n{}\n",     caCertPem);
                    TlsConfig.this.logger.info("Server certificate chain:\n{}\n", serverCertPem);
                    TlsConfig.this.logger.info("Server private key:\n{}\n",       serverPrivateKeyPem);

                    caCertificatePath     = Files.writeString(Files.createTempFile("ca",     ".crt"), caCertPem,           StandardOpenOption.CREATE);
                	serverCertificatePath = Files.writeString(Files.createTempFile("server", ".crt"), serverCertPem,       StandardOpenOption.CREATE);
                	serverPrivateKeyPath  = Files.writeString(Files.createTempFile("server", ".p8"),  serverPrivateKeyPem, StandardOpenOption.CREATE);
                } catch(Exception e) {
                    throw new RuntimeException("Save certs and keys to disk failed during Tomcat TLS customization", e);
                }
            	try { // Replace server.ssl.* properties in memory, pointing to the temp PEM files
                    final Ssl ssl = new Ssl();
                    ssl.setEnabled(true);
                    ssl.setProtocol(PROTOCOLS_TLS13_TLS12.get(0));
                    ssl.setClientAuth(ClientAuth.WANT);
                    ssl.setEnabledProtocols(PROTOCOLS_TLS13_TLS12.toArray(new String[0]));
                    ssl.setCiphers(CIPHERS_TLS13_TLS12.toArray(new String[0]));
                    ssl.setTrustCertificate(caCertificatePath.toFile().toString());
                    ssl.setCertificate(serverCertificatePath.toFile().toString());
                    ssl.setCertificatePrivateKey(serverPrivateKeyPath.toFile().toString());
                    this.setSsl(ssl);
                } catch(Exception e) {
                    throw new RuntimeException("Cert creation failed during Tomcat TLS customization", e);
                }
        	}
            // Must do this after, otherwise super code will cache objects built with original config
            super.customizeConnector(connector);
        }
    }

    // create "http://${server.address}:80" listener to redirect to "https://${server.address}:${server.port}"
    private Connector createHttpToHttpsRedirectConnector(final TlsSettings tlsSettings) {
        final Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);    // Http11NioProtocol
        connector.setRejectSuspiciousURIs(true);
        connector.setSecure(false);
        connector.setScheme("http");
		connector.setPort(HTTP_PORT.getAndIncrement());
        connector.setRedirectPort(tlsSettings.serverPort());
        connector.setProperty("bindOnInit", "false");
        return connector;
    }

    // create life cycle listener to log all Tomcat life cycle events
    private static class MyLifecycleLogger implements LifecycleListener {
        private Logger logger = LoggerFactory.getLogger(MyLifecycleLogger.class);
        @Override
        public void lifecycleEvent(final LifecycleEvent lifecycleEvent) {
        	if (!lifecycleEvent.getType().equals("periodic")) {
                this.logger.info("type={}", lifecycleEvent.getType());
        	}
        }
    }

    @Bean
    public TlsGeneratedConfig tlsGeneratedConfig(final TlsSettings tlsSettings) throws Exception {
    	final TlsAutoConfig tlsAutoConfig = tlsSettings.tlsAutoConfig;
		if (!tlsAutoConfig.enabled()) {
            return new TlsGeneratedConfig(null, null, null, null);
    	}
    	final String signingAlgorithm;
    	final Provider signingProvider;
        final KeyPairGenerator keyPairGenerator;
        if (tlsAutoConfig.algorithm() == null) {
        	throw new IllegalArgumentException("Unsupported server.ssl.auto-config.algorithm=" + tlsAutoConfig.algorithm());
        } else if (tlsAutoConfig.algorithm().startsWith("RSA")) {
        	final RsaGenAndSign rsaGenAndSign = rsaGenAndSign(tlsAutoConfig.algorithm());
        	keyPairGenerator = KeyPairGenerator.getInstance(rsaGenAndSign.genAlgorithm(), Security.getProvider(rsaGenAndSign.genProvider()));
            keyPairGenerator.initialize(rsaGenAndSign.keySize(), SECURE_RANDOM);
            signingAlgorithm = rsaGenAndSign.signingAlgorithm();
            signingProvider = Security.getProvider(rsaGenAndSign.signingProvider());
        } else if (tlsAutoConfig.algorithm().startsWith("EC")) {
        	final EcGenAndSign ecGenAndSign = ecGenAndSign(tlsAutoConfig.algorithm());
        	keyPairGenerator = KeyPairGenerator.getInstance(ecGenAndSign.genAlgorithm(), Security.getProvider(ecGenAndSign.genProvider()));
            keyPairGenerator.initialize(new ECGenParameterSpec(ecGenAndSign.curve()), SECURE_RANDOM);
            signingAlgorithm = ecGenAndSign.signingAlgorithm();
            signingProvider = Security.getProvider(ecGenAndSign.signingProvider());
        } else if (tlsAutoConfig.algorithm().equals("Ed25519")) {
        	// Caveat: Spring PEM_PARSERS does not have an PEM parser for Ed25519 (BEGIN PRIVATE KEY), so this doesn't work yet
        	keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", Security.getProvider("SunEC"));
            signingAlgorithm = "Ed25519";
            signingProvider = Security.getProvider("SunEC");
        } else {
        	throw new IllegalArgumentException("Unsupported server.ssl.auto-config.algorithm=" + tlsAutoConfig.algorithm());
        }

        // create root CA: key pair, and self-signed certificate containing root CA related extensions
        final KeyPair caKeyPair = keyPairGenerator.generateKeyPair();
		final X509Certificate caCert = createCert(
            Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
            Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
            new BigInteger(159, SECURE_RANDOM),
            caKeyPair.getPublic(),
            new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
            caKeyPair.getPrivate(),
            new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
            signingAlgorithm,
            signingProvider,
            new Extensions(new Extension[] {
                new Extension(Extension.basicConstraints, true, new BasicConstraints(0)           .toASN1Primitive().getEncoded()),
                new Extension(Extension.keyUsage,         true, new KeyUsage(KeyUsage.keyCertSign).toASN1Primitive().getEncoded())
            })
        );
		caCert.verify(caCert.getPublicKey());

        // create TLS Server: key pair, and CA-signed certificate containing TLS server related extensions
        final KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
        final X509Certificate serverCert = createCert(
            Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
            Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
            new BigInteger(159, SECURE_RANDOM),
            serverKeyPair.getPublic(),
            new X500Name(RFC4519Style.INSTANCE, "CN=server,DC=example.com"),
            caKeyPair.getPrivate(),
            new X500Name(RFC4519Style.INSTANCE, "DC=example.com"),
            signingAlgorithm,
            signingProvider,
            new Extensions(new Extension[] {
                new Extension(Extension.keyUsage,               true,  new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
                new Extension(Extension.extendedKeyUsage,       false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded()),
                new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                	new GeneralName(GeneralName.dNSName, "localhost"), new GeneralName(GeneralName.iPAddress, "127.0.0.1"), new GeneralName(GeneralName.iPAddress, "::1")
                }).toASN1Primitive().getEncoded())
            })
        );
		serverCert.verify(caCert.getPublicKey());

        return new TlsGeneratedConfig(caCert, caKeyPair.getPrivate(), serverCert, serverKeyPair.getPrivate());
    }

	private record RsaGenAndSign(String genAlgorithm, int keySize, String genProvider, String signingAlgorithm, String signingProvider) { }
	private RsaGenAndSign rsaGenAndSign(final String configuredAlgorithm) {
		return switch (configuredAlgorithm) {
			case  "RSA-1024" -> new RsaGenAndSign("RSA",  1024, "SunRsaSign", "SHA256withRSA", "SunRsaSign");
			case  "RSA-2048" -> new RsaGenAndSign("RSA",  2048, "SunRsaSign", "SHA256withRSA", "SunRsaSign");
		    case  "RSA-3072" -> new RsaGenAndSign("RSA",  3072, "SunRsaSign", "SHA256withRSA", "SunRsaSign");
		    case  "RSA-4096" -> new RsaGenAndSign("RSA",  4096, "SunRsaSign", "SHA384withRSA", "SunRsaSign");
		    case  "RSA-5120" -> new RsaGenAndSign("RSA",  5120, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case  "RSA-6144" -> new RsaGenAndSign("RSA",  6144, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case  "RSA-7168" -> new RsaGenAndSign("RSA",  7168, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case  "RSA-8192" -> new RsaGenAndSign("RSA",  8192, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case  "RSA-9216" -> new RsaGenAndSign("RSA",  9216, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-10240" -> new RsaGenAndSign("RSA", 10240, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-11264" -> new RsaGenAndSign("RSA", 11264, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-12288" -> new RsaGenAndSign("RSA", 12288, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-13312" -> new RsaGenAndSign("RSA", 13312, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-14336" -> new RsaGenAndSign("RSA", 14336, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-15360" -> new RsaGenAndSign("RSA", 15360, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    case "RSA-16384" -> new RsaGenAndSign("RSA", 16384, "SunRsaSign", "SHA512withRSA", "SunRsaSign");
		    default -> throw new IllegalArgumentException("Unsupported algorithm " + configuredAlgorithm);
		};
	}

	private record EcGenAndSign(String genAlgorithm, String curve, String genProvider, String signingAlgorithm, String signingProvider) { }
	private EcGenAndSign ecGenAndSign(final String configuredAlgorithm) {
		return switch (configuredAlgorithm) {
//		    case "EC-P256" -> new EcGenAndSign("EC", "secp256r1", "SunEC", "SHA256withECDSA", "SunEC");
		    case "EC-P384" -> new EcGenAndSign("EC", "secp384r1", "SunEC", "SHA384withECDSA", "SunEC");
//		    case "EC-P521" -> new EcGenAndSign("EC", "secp521r1", "SunEC", "SHA512withECDSA", "SunEC");
		    default -> throw new IllegalArgumentException("Unsupported algorithm " + configuredAlgorithm);
		};
	}

    // general purpose code for signing any X509Certificate (e.g. root CA, sub CA, end entity CA, etc)
    private static X509Certificate createCert(
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

    private static String toPem(final String type, final byte[]... payloads) {
        final Encoder mimeEncoder = Base64.getMimeEncoder(64, "\n".getBytes());
        final StringBuilder sb = new StringBuilder();
        for (final byte[] payload : payloads) {
            sb.append("-----BEGIN ").append(type).append("-----\n");
            sb.append(mimeEncoder.encodeToString(payload));
            sb.append("\n-----END ").append(type).append("-----\n");
        }
        return sb.toString();
    }

    @Bean
	public SSLContext clientSslContext(final TlsSettings tlsSettings, final TlsGeneratedConfig tlsGeneratedConfig) {
        if (tlsSettings.serverSslEnabled() || tlsSettings.tlsAutoConfig().enabled()) {
			try {
				final KeyStore trustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
				trustStore.load(null,  null);
				trustStore.setCertificateEntry("trustedca", tlsGeneratedConfig.x509CaCertificate);
	
				final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
				trustManagerFactory.init(trustStore);
				final TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
				
				final SSLContext clientSslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
				clientSslContext.init(null, trustManagers, SECURE_RANDOM);
				return clientSslContext;
			} catch(Throwable t) {
				throw new RuntimeException(t);
			}
        }
        return null;
	}

    private record TlsGeneratedConfig(
    	X509Certificate x509CaCertificate,     PrivateKey caPrivateKey,
    	X509Certificate x509ServerCertificate, PrivateKey serverPrivateKey
    ) { }

	@Lazy
	@Configuration
	public static class TlsSettings {
	    @Value(value="${server.address}")           public String        serverAddress;
	    @Value(value="${server.port}")              public int           serverPort;
	    @Value(value="${server.ssl.enabled:false}") public boolean       serverSslEnabled;
	    @Autowired                                  public TlsAutoConfig tlsAutoConfig;

		public String        serverAddress()    { return this.serverAddress;    }
		public int           serverPort()       { return this.serverPort;       }
		public boolean       serverSslEnabled() { return this.serverSslEnabled; }
		public TlsAutoConfig tlsAutoConfig()    { return this.tlsAutoConfig;    }

		@Bean
		public String baseUrl(@Value(value="${local.server.port}") final int localServerPort) {
		    final String protocol = (this.serverSslEnabled || this.tlsAutoConfig.enabled()) ? "https" : "http";
			return protocol + "://" + this.serverAddress + ":" + localServerPort;
		}

		@Configuration
		@ConfigurationProperties(prefix="server.ssl.auto-config")
		public static class TlsAutoConfig {
			private boolean       enabled = true;
			public  boolean       enabled()                      { return this.enabled; }
			public  TlsAutoConfig enabled(final boolean enabled) { this.enabled = enabled; return this; }

			private String        algorithm = "EC-P384";
			public  String        algorithm()                       { return this.algorithm; }
			public  TlsAutoConfig algorithm(final String algorithm) { this.algorithm = algorithm; return this; }
		}
	}
}

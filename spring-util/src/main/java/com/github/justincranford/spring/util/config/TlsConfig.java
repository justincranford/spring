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
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class TlsConfig {
    private Logger logger = LoggerFactory.getLogger(TlsConfig.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final AtomicInteger HTTP_PORT = new AtomicInteger(80);

    private record TlsAutoConfig(boolean enabled,
    	X509Certificate x509CaCertificate,     PrivateKey caPrivateKey,
    	X509Certificate x509ServerCertificate, PrivateKey serverPrivateKey
    ) { }

    @Value(value="${server.port}")
    public int serverPort;

    @Value(value="${server.ssl.enabled:false}")
    public boolean serverSslEnabled;

    @Bean
    public ServletWebServerFactory servletWebServerFactory(
        final ObjectProvider<TomcatConnectorCustomizer>          connectorCustomizers,
        final ObjectProvider<TomcatContextCustomizer>            contextCustomizers,
        final ObjectProvider<TomcatProtocolHandlerCustomizer<?>> protocolHandlerCustomizers,
        final TlsAutoConfig tlsAutoConfig
    ) throws Exception {
        // use ${server.ssl.*} settings to start Tomcat with auto-generated TLS server PEM files
        final TomcatServletWebServerFactory factory = new TlsTomcatServletWebServerFactory(tlsAutoConfig);

        // Same internal steps as ServletWebServerFactoryConfiguration$EmbeddedTomcat
        factory.getTomcatConnectorCustomizers().addAll(connectorCustomizers.orderedStream().toList());
        factory.getTomcatContextCustomizers().addAll(contextCustomizers.orderedStream().toList());
        factory.getTomcatProtocolHandlerCustomizers().addAll(protocolHandlerCustomizers.orderedStream().toList());

        // add "http://${server.address}:80" listener to redirect to "https://${server.address}:${server.port}"
        if (tlsAutoConfig.enabled() || this.serverSslEnabled) {
            factory.addAdditionalTomcatConnectors(this.createHttpToHttpsRedirectConnector());
        }

        // add life cycle listener to log all Tomcat life cycle events
        factory.setContextLifecycleListeners(Stream.concat(factory.getContextLifecycleListeners().stream(), List.of(new MyLifecycleLogger()).stream()).toList());

        return factory;
    }

    @Bean
    public TlsAutoConfig tlsAutoConfig(
    	@Value(value="${server.ssl.auto-generate-certificates:false}") final boolean serverSslAutoGenerateCertificates
    ) throws Exception {
    	if (!serverSslAutoGenerateCertificates) {
            return new TlsAutoConfig(false, null, null, null, null);
    	}
    	// TODO EC-P384
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", Security.getProvider("SunRsaSign"));
        keyPairGenerator.initialize(2048, SECURE_RANDOM);

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
            "SHA256withRSA",
            Security.getProvider("SunRsaSign"),
            new Extensions(new Extension[] {
                new Extension(Extension.basicConstraints, true, new BasicConstraints(0)           .toASN1Primitive().getEncoded()),
                new Extension(Extension.keyUsage,         true, new KeyUsage(KeyUsage.keyCertSign).toASN1Primitive().getEncoded())
            })
        );

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
            "SHA256withRSA",
            Security.getProvider("SunRsaSign"),
            new Extensions(new Extension[] {
                new Extension(Extension.keyUsage,               true,  new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
                new Extension(Extension.extendedKeyUsage,       false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded()),
                new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                	new GeneralName(GeneralName.dNSName, "localhost"), new GeneralName(GeneralName.iPAddress, "127.0.0.1"), new GeneralName(GeneralName.iPAddress, "::1")
                }).toASN1Primitive().getEncoded())
            })
        );

        return new TlsAutoConfig(true, caCert, caKeyPair.getPrivate(), serverCert, serverKeyPair.getPrivate());
    }

    @Bean
	public SSLContext clientSslContext(final TlsAutoConfig tlsAutoConfig) {
    	if (!tlsAutoConfig.enabled()) {
    		return null;
    	}
		try {
			final KeyStore trustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
			trustStore.load(null,  null);
			trustStore.setCertificateEntry("trustedca", tlsAutoConfig.x509CaCertificate);

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

    // create ${server.ssl.*} settings to start Tomcat with auto-generated TLS server PEM files
    private class TlsTomcatServletWebServerFactory extends TomcatServletWebServerFactory {
        // Mozilla recommended "intermediate" ciphersuites (January 2023)
        private static final List<String> PROTOCOLS_TLS13_ONLY = List.of("TLSv1.3");
        private static final List<String> PROTOCOLS_TLS12_ONLY = List.of("TLSv1.2");
        private static final List<String> PROTOCOLS_TLS13_TLS12 = Stream.concat(PROTOCOLS_TLS13_ONLY.stream(), PROTOCOLS_TLS12_ONLY.stream()).toList();
        private static final List<String> CIPHERS_TLS13_ONLY = List.of("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256");
        private static final List<String> CIPHERS_TLS12_ONLY = List.of("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256");
        private static final List<String> CIPHERS_TLS13_TLS12 = Stream.concat(CIPHERS_TLS13_ONLY.stream(), CIPHERS_TLS12_ONLY.stream()).toList();

        private final TlsAutoConfig tlsAutoConfig;
        public TlsTomcatServletWebServerFactory(final TlsAutoConfig tlsAutoConfig) {
        	this.tlsAutoConfig = tlsAutoConfig;
        }

        @Override
        protected void postProcessContext(final Context servletContext) {
            if (this.tlsAutoConfig.enabled() || TlsConfig.this.serverSslEnabled) {
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
        	if (this.tlsAutoConfig.enabled()) {
        		final Path caCertificatePath;
        		final Path serverCertificatePath;
        		final Path serverPrivateKeyPath;
            	try {
                    // Encode server privateKey, server cert, and root CA cert as PEM
                    final String caCertPem           = toPem("CERTIFICATE",     this.tlsAutoConfig.x509CaCertificate().getEncoded());
                    final String serverCertPem       = toPem("CERTIFICATE",     this.tlsAutoConfig.x509ServerCertificate().getEncoded());
                    final String serverPrivateKeyPem = toPem("RSA PRIVATE KEY", PrivateKeyInfo.getInstance(this.tlsAutoConfig.serverPrivateKey().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());

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
                    ssl.setProtocol(PROTOCOLS_TLS13_ONLY.get(0));
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
    private Connector createHttpToHttpsRedirectConnector() {
        final Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);    // Http11NioProtocol
        connector.setRejectSuspiciousURIs(true);
        connector.setSecure(false);
        connector.setScheme("http");
		connector.setPort(HTTP_PORT.getAndIncrement());
        connector.setRedirectPort(this.serverPort);
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
}

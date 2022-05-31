package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.file.Files;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Specializes;
import javax.inject.Inject;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.io.PropertiesLoader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.eclipse.microprofile.jwt.config.Names;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

@Specializes
@ApplicationScoped
public class AzureKidMapper extends KidMapper {

  @Inject
  private GeronimoJwtAuthConfig config;

  private final ConcurrentMap<String, String> keyMapping = new ConcurrentHashMap<>();
  private final Map<String, Collection<String>> issuerMapping = new HashMap<>();
  private String defaultKey;
  private Set<String> defaultIssuers;
  private String jwksUrl;

  @PostConstruct
  private void init() {
    jwksUrl = config.read("keys.location", null);
    jwksUrl = jwksUrl.trim();
    try {
      cacheJsonWebKeySet();
    } catch (Exception e) {
      e.printStackTrace();
    }

    ofNullable(config.read("kids.key.mapping", null))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .map(PropertiesLoader::load)
      .ifPresent(props -> props.stringPropertyNames()
        .forEach(k -> keyMapping.put(k, loadKey(props.getProperty(k)))));
    ofNullable(config.read("kids.issuer.mapping", null))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .map(PropertiesLoader::load)
      .ifPresent(props -> props.stringPropertyNames()
        .forEach(k -> {
          issuerMapping.put(k, Stream.of(props.getProperty(k).split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toSet()));
        }));
    defaultIssuers = ofNullable(config.read("org.eclipse.microprofile.authentication.JWT.issuers", null))
      .map(s -> Stream.of(s.split(","))
        .map(String::trim)
        .filter(it -> !it.isEmpty())
        .collect(Collectors.toSet()))
      .orElseGet(HashSet::new);
    ofNullable(config.read("issuer.default", config.read(Names.ISSUER, null))).ifPresent(defaultIssuers::add);
    defaultKey = config.read("public-key.default", config.read(Names.VERIFIER_PUBLIC_KEY, null));
  }

  private void cacheJsonWebKeySet() {
    int httpConnectTimeoutMs = 5_000;
    int httpReadTimeoutMs = 5_000;
    int httpSizeLimitBytes = 100_000;
    String headerAndTrailerText = "PUBLIC KEY";

    boolean doesKeySetUrlExists = jwksUrl != null && !jwksUrl.isEmpty();

    if (doesKeySetUrlExists) {
      try {
        JWKSet publicKeys = JWKSet.load(new URL(jwksUrl), httpConnectTimeoutMs, httpReadTimeoutMs, httpSizeLimitBytes);

        for (JWK jsonWebKeySet : publicKeys.getKeys()) {
          PublicKey publicKey = jsonWebKeySet.toRSAKey().toPublicKey();

          PemObject pemObject = new PemObject(headerAndTrailerText, publicKey.getEncoded());
          ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
          PemWriter pemWriter = new PemWriter(new OutputStreamWriter(byteArrayOutputStream));
          pemWriter.writeObject(pemObject);
          pemWriter.close();
          String pemKey = byteArrayOutputStream.toString();
          pemKey = pemKey.replace("\r","");
          pemKey = pemKey.replace("\n","");
          keyMapping.put(jsonWebKeySet.getKeyID(), pemKey);
        }
      } catch (IOException | ParseException | JOSEException e) {
        e.printStackTrace();
      }
    }
  }

  public String loadKey(final String property) {
    String value = keyMapping.get(property);
    if (value == null) {
      value = tryLoad(property);
      if (value != null && !property.equals(value) /* else we can leak easily*/) {
        keyMapping.putIfAbsent(property, value);
      } else if (defaultKey != null) {
        value = defaultKey;
      }
    }
    return value;
  }

  public Collection<String> loadIssuers(final String property) {
    return issuerMapping.getOrDefault(property, defaultIssuers);
  }

  private String tryLoad(final String value) {
    // try external file
    final File file = new File(value);
    if (file.exists()) {
      try {
        return Files.readAllLines(file.toPath()).stream().collect(joining("\n"));
      } catch (final IOException e) {
        throw new IllegalArgumentException(e);
      }
    }

    // if not found try classpath resource
    try (final InputStream stream = Thread.currentThread().getContextClassLoader()
      .getResourceAsStream(value)) {
      if (stream != null) {
        return new BufferedReader(new InputStreamReader(stream)).lines().collect(joining("\n"));
      }
    } catch (final IOException e) {
      throw new IllegalArgumentException(e);
    }

    // else direct value
    return value;
  }
}
package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;

import static javax.ws.rs.client.ClientBuilder.newClient;
import static org.testng.Assert.assertEquals;

public class RefreshIntervalTest extends Arquillian {

	private static JwksServer jwksServer;

    @Deployment()
    public static WebArchive createDeployment() throws Exception {
        jwksServer = new JwksServer();
        jwksServer.start();
        System.setProperty("mp.jwt.verify.publickey.location", "http://localhost:" + jwksServer.getPort() + "/jwks.json");
        System.setProperty("geronimo.jwt-auth.jwks.invalidation.interval", "1");
        return ShrinkWrap
            .create(WebArchive.class)
            .addAsWebInfResource("META-INF/beans.xml", "beans.xml")
            .addClasses(JwtParser.class, KidMapper.class, PublicKeyResource.class);
    }

    @AfterClass
    static void stopJwksServer() throws IOException {
        jwksServer.stop();
    }

    @ArquillianResource
    private URL serverUrl;

    @Test
    @RunAsClient
    void refreshIntervalTest() throws URISyntaxException {
        String expectedKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyzNurU19lqnYhx5QI72sIX1lh8cTehTmboC+DLG7UuaUHqs096M754HtP2IiHFcIQqwYNzHgKmjmfGdbk9JBkz/DNeDVsA5nc7qTnsSgULXTxwHSF286IJdco5kasaJm4Xurlm3V+2oiTugraBsi1J0Ht0OtHgJIlIaGxK7mY/QIDAQAB-----END PUBLIC KEY-----";

        String key = newClient().target(serverUrl.toURI()).path("public-keys").path("orange-1234").request().get(String.class);
        
        assertEquals(key, expectedKey);
    }

}
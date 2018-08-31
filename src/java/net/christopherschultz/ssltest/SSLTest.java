/*
 * SSLTest.java
 *
 * Tests servers for SSL/TLS protocol and cipher support.
 *
 * Copyright (c) 2015 Christopher Schultz
 *
 * Christopher Schultz licenses this file to You under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.christopherschultz.ssltest;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * A driver class to test a server's SSL/TLS support.
 *
 * Usage: java SSLTest [opts] host[:port]
 *
 * Try "java SSLTest -h" for help.
 *
 * This tester will attempts to handshake with the target host with all
 * available protocols and ciphers and report which ones were accepted and
 * which were rejected. An HTTP connection is never fully made, so these
 * connections should not flood the host's access log with entries.
 *
 * @author Christopher Schultz
 */
public class SSLTest
{
    private static void usage()
    {
        System.out.println("Usage: java " + SSLTest.class + " [opts] host[:port]");
        System.out.println();
        System.out.println("-sslprotocol                 Sets the SSL/TLS protocol to be used (e.g. SSL, TLS, SSLv3, TLSv1.2, etc.)");
        System.out.println("-enabledprotocols protocols  Sets individual SSL/TLS ptotocols that should be enabled");
        System.out.println("-ciphers cipherspec          A comma-separated list of SSL/TLS ciphers");
        System.out.println("-connectonly                 Don't scan; only connect a single time");

        System.out.println("-keystore                    Sets the key store for connections (for TLS client certificates)");
        System.out.println("-keystoretype type           Sets the type for the key store");
        System.out.println("-keystorepassword pass       Sets the password for the key store");
        System.out.println("-keystoreprovider provider   Sets the crypto provider for the key store");

        System.out.println("-truststore                  Sets the trust store for connections");
        System.out.println("-truststoretype type         Sets the type for the trust store");
        System.out.println("-truststorepassword pass     Sets the password for the trust store");
        System.out.println("-truststorealgorithm alg     Sets the algorithm for the trust store");
        System.out.println("-truststoreprovider provider Sets the crypto provider for the trust store");
        System.out.println("-crlfilename                 Sets the CRL filename to use for the trust store");

        System.out.println("-check-certificate           Checks certificate trust (default: false)");
        System.out.println("-no-check-certificate        Ignores certificate errors (default: true)");
        System.out.println("-verify-hostname             Verifies certificate hostname (default: false)");
        System.out.println("-no-verify-hostname          Ignores hostname mismatches (default: true)");

        System.out.println("-showsslerrors               Show SSL/TLS error details");
        System.out.println("-showhandshakeerrors         Show SSL/TLS handshake error details");
        System.out.println("-showerrors                  Show all connection error details");
        System.out.println("-hiderejects                 Only show protocols/ciphers which were successful");
        System.out.println();
        System.out.println("-h -help --help              Shows this help message");
    }

    public static void main(String[] args)
        throws Exception
    {
        // Enable all algorithms + protocols
        // System.setProperty("jdk.tls.client.protocols", "SSLv2Hello,SSLv3,TLSv1,TLSv1.1,TLSv1.2");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        Security.setProperty("crypto.policy", "unlimited"); // For Java 9+

        int connectTimeout = 0; // default = infinite
        int readTimeout = 1000;

        boolean disableHostnameVerification = true;
        boolean disableCertificateChecking = true;
        boolean hideRejects = false;

        String trustStoreFilename = System.getProperty("javax.net.ssl.trustStore");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
        String trustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
        String trustStoreProvider = System.getProperty("javax.net.ssl.trustStoreProvider");
        String trustStoreAlgorithm = null;
        String keyStoreFilename = System.getProperty("javax.net.ssl.keyStore");
        String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");
        String keyStoreType = System.getProperty("javax.net.ssl.keyStoreType");
        String keyStoreProvider = System.getProperty("javax.net.ssl.keyStoreProvider");
        String sslProtocol = "TLS";
        String[] sslEnabledProtocols = null; // new String[] { "SSLv2", "SSLv2hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" };
        String[] sslCipherSuites = null; // Default = default for protocol
        String crlFilename = null;
        boolean showCerts = false;
        boolean connectOnly = false;
        boolean showHandshakeErrors = false;
        boolean showSSLErrors = false;
        boolean showErrors = false;

        if(args.length < 1)
        {
            usage();
            System.exit(0);
        }

        int argIndex;
        for(argIndex = 0; argIndex < args.length; ++argIndex)
        {
            String arg = args[argIndex];

            if(!arg.startsWith("-"))
                break;
            else if("--".equals(arg))
                break;
            else if("-no-check-certificate".equals(arg))
                disableCertificateChecking = true;
            else if("-check-certificate".equals(arg))
                disableCertificateChecking = false;
            else if("-no-verify-hostname".equals(arg))
                disableHostnameVerification = true;
            else if("-verify-hostname".equals(arg))
                disableHostnameVerification = false;
            else if("-sslprotocol".equals(arg))
                sslProtocol = args[++argIndex];
            else if("-enabledprotocols".equals(arg))
                sslEnabledProtocols = args[++argIndex].split("\\s*,\\s*");
            else if("-ciphers".equals(arg))
                sslCipherSuites = args[++argIndex].split("\\s*,\\s*");
            else if("-connecttimeout".equals(arg))
                connectTimeout = Integer.parseInt(args[++argIndex]);
            else if("-readtimeout".equals(arg))
                readTimeout = Integer.parseInt(args[++argIndex]);
            else if("-truststore".equals(arg))
                trustStoreFilename = args[++argIndex];
            else if("-truststoretype".equals(arg))
                trustStoreType = args[++argIndex];
            else if("-truststorepassword".equals(arg))
                trustStorePassword = args[++argIndex];
            else if("-truststoreprovider".equals(arg))
                trustStoreProvider = args[++argIndex];
            else if("-truststorealgorithm".equals(arg))
                trustStoreAlgorithm = args[++argIndex];
            else if("-crlfilename".equals(arg))
                crlFilename = args[++argIndex];
            else if("-keystore".equals(arg))
                keyStoreFilename = args[++argIndex];
            else if("-keystoretype".equals(arg))
                keyStoreType = args[++argIndex];
            else if("-keystorepassword".equals(arg))
                keyStorePassword = args[++argIndex];
            else if("-keystoreprovider".equals(arg))
                keyStoreProvider = args[++argIndex];
            else if("-showcerts".equals(arg))
                showCerts = true;
            else if("-showerrors".equals(arg))
                showErrors = showHandshakeErrors = showSSLErrors = true;
            else if("-showhandshakeerrors".equals(arg))
                showHandshakeErrors = true;
            else if("-showsslerrors".equals(arg))
                showSSLErrors = true;
            else if("-connectonly".equals(arg))
                connectOnly = true;
            else if("-hiderejects".equals(arg))
                hideRejects = true;
            else if("--help".equals(arg)
                    || "-h".equals(arg)
                    || "-help".equals(arg))
            {
                usage();
                System.exit(0);
            }
            else
            {
                System.err.println("Unrecognized option: " + arg);
                System.exit(1);
            }
        }

        if(argIndex >= args.length)
        {
            System.err.println("Unexpected additional arguments: "
                               + java.util.Arrays.asList(args).subList(argIndex, args.length));

            usage();
            System.exit(1);
        }

        // TODO: Does this actually do anything?
        if(disableHostnameVerification)
            SSLUtils.disableSSLHostnameVerification();

        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        if(null != keyStoreFilename)
        {
            if(null == keyStoreType)
                keyStoreType = "JKS";

            KeyStore keyStore = SSLUtils.getStore(keyStoreFilename, keyStorePassword, keyStoreType, keyStoreProvider);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] kpwd;
            if(null != keyStorePassword && 0 < keyStorePassword.length())
                kpwd = keyStorePassword.toCharArray();
            else
                kpwd = null;
            kmf.init(keyStore, kpwd);
            keyManagers = kmf.getKeyManagers();
        }
        else
            keyManagers = null;

        if(disableCertificateChecking
           || "true".equalsIgnoreCase(System.getProperty("disable.ssl.cert.checks")))
        {
            trustManagers = SSLUtils.getTrustAllCertsTrustManagers();
        }
        else if(null != trustStoreFilename)
        {
            if(null == trustStoreType)
                trustStoreType = "JKS";

            trustManagers = SSLUtils.getTrustManagers(trustStoreFilename, trustStorePassword, trustStoreType, trustStoreProvider, trustStoreAlgorithm, null, crlFilename);
        }
        else
            trustManagers = null;

        int port = 443;
        String host = args[argIndex];

        int pos = host.indexOf(':');
        if(pos > 0)
        {
            port = Integer.parseInt(host.substring(pos + 1));
            host = host.substring(0, pos);
        }

        try
        {
            InetAddress[] iaddrs = InetAddress.getAllByName(host);
            if(null == iaddrs || 0 == iaddrs.length)
            {
                System.err.println("Unknown hostname: " + host);
                System.exit(1);
            }
            if(1 == iaddrs.length)
                System.out.println("Host [" + host + "] resolves to address [" + iaddrs[0].getHostAddress() + "]");
            else
            {
                System.out.print("Host [" + host + "] resolves to addresses ");
                for(int i=0; i<iaddrs.length; ++i)
                {
                    if(i > 0) System.out.print(", ");
                    System.out.print("[" + iaddrs[i].getHostAddress() + "]");
                }
                System.out.println();
            }
        }
        catch (UnknownHostException uhe)
        {
            System.err.println("Unknown hostname: " + host);
            System.exit(1);
        }

        InetSocketAddress address = new InetSocketAddress(host, port);
        if(address.isUnresolved())
        {
            System.err.println("Unknown hostname: " + host);
            System.exit(1);
        }

        List<String> supportedProtocols;

        if(null == sslEnabledProtocols)
        {
            // Auto-detect supported protocols
            ArrayList<String> protocols = new ArrayList<String>();
            // TODO: Allow the specification of a specific provider (or set?)
            for(Provider provider : Security.getProviders())
            {
                for(Object prop : provider.keySet())
                {
                    String key = (String)prop;
                    if(key.startsWith("SSLContext.")
                       && !"SSLContext.Default".equals(key)
                       && key.matches(".*[0-9].*"))
                        protocols.add(key.substring("SSLContext.".length()));
                    else if(key.startsWith("Alg.Alias.SSLContext.")
                            && key.matches(".*[0-9].*"))
                        protocols.add(key.substring("Alg.Alias.SSLContext.".length()));
                }
            }
            Collections.sort(protocols); // Should give us a nice sort-order by default
            System.out.println("Auto-detected client-supported protocols: " + protocols);
            supportedProtocols = protocols;
            sslEnabledProtocols = supportedProtocols.toArray(new String[supportedProtocols.size()]);
        }
        else
        {
            supportedProtocols = new ArrayList<String>(Arrays.asList(sslEnabledProtocols));
        }

        // Warn about operating under limited cryptographic controls.
        if(Integer.MAX_VALUE > Cipher.getMaxAllowedKeyLength("foo"))
            System.err.println("[warning] Client is running under LIMITED cryptographic controls. Consider installing the JCE Unlimited Strength Jurisdiction Policy Files.");

        SecureRandom rand = SecureRandom.getInstance("NativePRNG");

        if(!connectOnly) {
            System.out.println("Testing server " + host + ":" + port);

            String reportFormat = "%9s %8s %s%n";
            String errorReportFormat = "%9s %8s %s %s%n";

            System.out.print(String.format(reportFormat, "Supported", "Protocol", "Cipher"));

        HashSet<String> cipherSuites = new HashSet<String>();

        boolean stop = false;

        for(int i=0; i<sslEnabledProtocols.length && !stop; ++i)
        {
            String protocol = sslEnabledProtocols[i];

            String[] supportedCipherSuites = null;

            try
            {
                supportedCipherSuites = getJVMSupportedCipherSuites(protocol, rand);
            }
            catch (NoSuchAlgorithmException nsae)
            {
                System.out.print(String.format(reportFormat, "-----", protocol, " Not supported by client"));
                supportedProtocols.remove(protocol);
                continue;
            }
            catch (Exception e)
            {
                e.printStackTrace();
                continue; // Skip this protocol
            }

            // Restrict cipher suites to those specified by sslCipherSuites
            cipherSuites.clear();
            cipherSuites.addAll(Arrays.asList(supportedCipherSuites));
            if(null != sslCipherSuites)
                cipherSuites.retainAll(Arrays.asList(sslCipherSuites));

            if(cipherSuites.isEmpty())
            {
                System.err.println("No overlapping cipher suites found for protocol " + protocol);
                supportedProtocols.remove(protocol);
                continue; // Go to the next protocol
            }

            for(Iterator<String> j=cipherSuites.iterator(); j.hasNext() && !stop; )
            {
                String cipherSuite = j.next();
                String status;

                SSLSocketFactory sf = SSLUtils.getSSLSocketFactory(protocol,
                                                                   new String[] { protocol },
                                                                   new String[] { cipherSuite },
                                                                   rand,
                                                                   trustManagers,
                                                                   keyManagers);

                SSLSocket socket = null;
                String error = null;

                try
                {
                    socket = createSSLSocket(address, host, port, connectTimeout, readTimeout, sf);
/*
socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent evt)
    {
        System.err.println("======== COMPLETED HANDSHAKE, SESSION=" + evt.getSession());
        System.err.println("HANDSHAKE THREADNAME: " + Thread.currentThread().getName());
        SSLSocket socket = evt.getSocket();
        System.err.println("parameters=" + socket.getSSLParameters());
        System.err.println(java.util.Arrays.asList(socket.getSSLParameters().getProtocols()));
        System.err.println(java.util.Arrays.asList(socket.getSSLParameters().getCipherSuites()));
        System.err.println("constraints=" + socket.getSSLParameters().getAlgorithmConstraints());
        System.err.println("endpoint id algo=" + socket.getSSLParameters().getEndpointIdentificationAlgorithm());
        System.err.println("server names=" + socket.getSSLParameters().getServerNames());
try
{
    System.err.println("principal=" + evt.getPeerPrincipal());
        for(Certificate cert : evt.getSession().getPeerCertificates())
        {
            if("X.509".equals(cert.getType()))
            {
                X509Certificate x509cert = (X509Certificate)cert;
                System.out.println("==HS== certificate subject=" + x509cert.getSubjectDN());
                if(null != x509cert.getSigAlgParams())
                    System.out.println("==HS== parameters: " + Arrays.asList(x509cert.getSigAlgParams()));
            }
            else
                System.out.println("==HS== Unrecognized cert type: " + cert.getType());

            PublicKey pk = cert.getPublicKey();
            if("RSA".equals(pk.getAlgorithm()))
            {
                RSAPublicKey rsa = (RSAPublicKey)pk;
                System.out.println("==HS== RSA mod length: " + rsa.getModulus().bitLength());
                System.out.println("==HS== RSA format " + rsa.getFormat());
                System.out.println("==HS== RSA encoded: " + Arrays.asList(rsa.getEncoded()));
            } else {
                System.out.println("==HS== UNKNOWN Certificate algorithm: " + pk.getAlgorithm());
            }
            System.out.println("==HS== Implementing PK class: " + pk.getClass());
        }
}
catch (SSLPeerUnverifiedException e)
{
    e.printStackTrace();
}
    } });
//    */
                    socket.startHandshake();

                    /*
                    System.err.println(socket.getSSLParameters());//.getEndpointIdentificationAlgorithm()
                    System.err.println(java.util.Arrays.asList(socket.getSSLParameters().getProtocols()));
                    System.err.println(java.util.Arrays.asList(socket.getSSLParameters().getCipherSuites()));
                    System.err.println(socket.getSSLParameters().getAlgorithmConstraints());
                    System.err.println(socket.getSSLParameters().getEndpointIdentificationAlgorithm());
                    System.err.println(socket.getSSLParameters().getServerNames());
                    //System.err.println("cert 0: " + socket.getSession().getPeerCertificates()[0]);
                    System.err.println(socket.getSession());
*/

                    SSLSession sess = socket.getSession();
//                    Thread.currentThread().sleep(200);System.exit(0);
//                    System.err.println("NORMAL SESSION = " + sess);
//                    System.err.println("MAIN THREADNAME: " + Thread.currentThread().getName());
                    assert protocol.equals(sess.getProtocol());
                    assert cipherSuite.equals(sess.getCipherSuite());

                    /*
                    Certificate[] certs = sess.getPeerCertificates();
                    int certCount = certs.length;
                    Certificate cert = certs[certCount - 1];
                    // for(Certificate cert : certs)
                    {
                        //                        System.out.println("cert format: " + cert.getPublicKey().getFormat());
                        //                        System.out.println("Implementing class: " + cert.getClass().getName());
                        if("X.509".equals(cert.getType()))
                        {
                            X509Certificate x509cert = (X509Certificate)cert;
                            if(null != x509cert.getSigAlgParams())
                                System.out.println("parameters: " + Arrays.asList(x509cert.getSigAlgParams()));
                        }
                        else
                            System.out.println("Unrecognized cert type: " + cert.getType());
                        PublicKey pk = cert.getPublicKey();
                        if("RSA".equals(pk.getAlgorithm()))
                        {
                            RSAPublicKey rsa = (RSAPublicKey)pk;
                            System.out.println("RSA mod length: " + rsa.getModulus().bitLength());
                        } else {
                            System.out.println("UNKNOWN Certificate algorithm: " + pk.getAlgorithm());
                        }
                        System.out.println("Implementing PK class: " + pk.getClass());
                    }
*/
                    status = "Accepted";
                }
                catch (SSLHandshakeException she)
                {
                    Throwable cause = she.getCause();
                    if(null != cause && cause instanceof CertificateException) {
                        status = "Untrusted";
                        error = "Server certificate is not trusted. All other connections will fail similarly.";
                        stop = true;
                    } else
                        status = "Rejected";

                    if(showHandshakeErrors)
                        error = "SHE: " + she.getLocalizedMessage() + ", type=" + she.getClass().getName() + ", nested=" + she.getCause();
                }
                catch (SSLException ssle)
                {
                    if(showSSLErrors)
                        error = "SE: " + ssle.getLocalizedMessage();

                    status = "Rejected";
                }
                catch (SocketTimeoutException ste)
                {
                    if(showErrors)
                        error = "SocketException" + ste.getLocalizedMessage();

                    status = "Timeout";
                }
                catch (SocketException se)
                {
                    if(showErrors)
                        error = se.getLocalizedMessage();

                    status = "Failed";
                }
                catch (IOException ioe)
                {
                    if(showErrors)
                        error = ioe.getLocalizedMessage();

                    ioe.printStackTrace();
                    status = "Failed";
                }
                catch (Exception e)
                {
                    if(showErrors)
                        error = e.getLocalizedMessage();

                    e.printStackTrace();
                    status = "Failed";
                }
                finally
                {
                    if(null != socket) try { socket.close(); }
                    catch (IOException ioe) { ioe.printStackTrace(); }
                }

                if(null != error)
                    System.out.print(String.format(errorReportFormat,
                                                   status,
                                                   protocol,
                                                   cipherSuite,
                                                   error));
                else if(!hideRejects || !"Rejected".equals(status))
                    System.out.print(String.format(reportFormat,
                                                   status,
                                                   protocol,
                                                   cipherSuite));
            }
        }

        if(supportedProtocols.isEmpty())
        {
            System.err.println("This client supports none of the requested protocols: "
                               + Arrays.asList(sslEnabledProtocols));
            System.err.println("Exiting.");
            System.exit(1);
        }
        }

        // Now get generic and allow the server to decide on the protocol and cipher suite
        String[] protocolsToTry = supportedProtocols.toArray(new String[supportedProtocols.size()]);

        // If the user didn't provide a specific set of cipher suites,
        // use the system's *complete* set of supported cipher suites.
        if(null == sslCipherSuites)
            sslCipherSuites = getJVMSupportedCipherSuites(sslProtocol, rand);

        // Java 9-10 doesn't seem to like having any DTLS protocols
        // in the list of enabled protocols.
        // Java 11 seems okay with DTLS being in the mix.
        String javaVersion = System.getProperty("java.vm.specification.version", null);
        if(null != javaVersion) {
            double jv = Double.parseDouble(javaVersion);
            if(jv == 9 || jv == 10) {
                ArrayList<String> cleansedProtocolNames = new ArrayList<String>(protocolsToTry.length);
                for(String protocol : protocolsToTry)
                    if(!protocol.startsWith("DTLS"))
                        cleansedProtocolNames.add(protocol);

                protocolsToTry = cleansedProtocolNames.toArray(new String[cleansedProtocolNames.size()]);
            }
        }

        SSLSocketFactory sf = SSLUtils.getSSLSocketFactory(sslProtocol,
                                                           protocolsToTry,
                                                           sslCipherSuites,
                                                           rand,
                                                           trustManagers,
                                                           keyManagers);

        SSLSocket socket = null;

        try
        {
            socket = createSSLSocket(address, host, port, connectTimeout, readTimeout, sf);

            try
            {
                socket.startHandshake();

                System.out.print("Given this client's capabilities ("
                        + supportedProtocols
                        + "), the server prefers protocol=");
                System.out.print(socket.getSession().getProtocol());
                System.out.print(", cipher=");
                System.out.println(socket.getSession().getCipherSuite());

                if(showCerts)
                {
                    System.out.println("Attempting to check certificates:");
                    Certificate[] certs = socket.getSession().getPeerCertificates();
                    for(Certificate cert : certs)
                    {
                        String certType = cert.getType();
                        System.out.println("Certificate: " + certType);
                        if("X.509".equals(certType))
                        {
                            X509Certificate x509 = (X509Certificate)cert;
                            System.out.println("Subject: " + x509.getSubjectDN());
                            System.out.println("Issuer: " + x509.getIssuerDN());
                            System.out.println("Serial: " + x509.getSerialNumber());
                            try {
                                x509.checkValidity();
                                System.out.println("Certificate is currently valid.");
                            } catch (CertificateException ce) {
                                System.out.println("WARNING: certificate is not valid: " + ce.getMessage());
                            }
                            //                   System.out.println("Signature: " + toHexString(x509.getSignature()));
                            //                   System.out.println("cert bytes: " + toHexString(cert.getEncoded()));
                            //                   System.out.println("cert bytes: " + cert.getPublicKey());
                        }
                        else
                        {
                            System.out.println("Unknown certificate type (" + cert.getType() + "): " + cert);
                        }
                    }

                    if(certs instanceof X509Certificate[]
                       && checkTrust((X509Certificate[])certs, trustManagers))
                        System.out.println("Certificate chain is trusted");
                    else
                        System.out.println("Certificate chain is UNTRUSTED");
                }
            }
            catch (SocketException se)
            {
                System.out.println("Error during connection handshake for protocols "
                                   + supportedProtocols
                                   + ": server likely does not support any of these protocols.");

                if(showCerts)
                    System.out.println("Unable to show server certificate without a successful handshake.");
            } catch (SSLHandshakeException she) {
                Throwable cause = she.getCause();
                if(cause instanceof CertificateException)
                    System.out.println("Server certificate is not trusted, cannot complete handshake. Try -no-check-certificate");

                if(showCerts)
                    System.out.println("Unable to show server certificate without a successful handshake.");
            }
        }
        finally
        {
            if (null != socket) try { socket.close(); }
            catch (IOException ioe) { ioe.printStackTrace(); }
        }

/*
        System.out.println("Attempting to determine the server's SSLv2 capabilities using OpenSSL s_client...");
        // Try an SSLv2 connection with OpenSSL's s_client, just for kicks.
        Process p = Runtime.getRuntime().exec(new String[] {
                "openssl", "s_client",
                "-ssl2",
                "-connect", host + ":" + port }
        );
        // Make sure this process isn't trying to read from stdin
        OutputStream out = p.getOutputStream();
        out.close();

        InputStream stdout = p.getInputStream();
        InputStream stderr = p.getErrorStream();

        // Use NIO so we don't block like an idiot
        ReadableByteChannel in = Channels.newChannel(stdout);
        ReadableByteChannel err = Channels.newChannel(stderr);
        ByteBuffer buf = ByteBuffer.allocate(4096);
        StringBuilder outsb = new StringBuilder();
        StringBuilder errsb = new StringBuilder();

        byte[] buffer = new byte[4096];
        boolean outDone = false, errDone = false;

        do
        {
            int read;
*/
/*
            if(!outDone) {
                read = in.read(buf);
                if(-1 != read) {
                    buf.flip();
                    buf.get(buffer, 0, read);
                    System.out.println("Read " + read + " from stdout");
                    outsb.append(new String(buffer, 0, read));
                } else {
                    outDone = true;
                    // System.out.println("Output stream is done");
                }

                buf.flip();
            }
*/
/*
outDone = true;
            if(!errDone) {
                read = err.read(buf);
                if(-1 == read) {
                    buf.flip();
                    buf.get(buffer, 0, read);
                    System.out.println("Read " + read + " from stderr");
                    errsb.append(new String(buffer, 0, read));
                } else {
                    errDone = true;
                    // System.out.println("Error stream is done");
                }

                buf.flip();
            }

            Thread.sleep(100);
        } while(!outDone && !errDone);
        int status = p.waitFor();
        System.out.println("finally read " + err.read(buf) + " from stderr");
        if(0 < outsb.length())
            System.out.print("STDOUT: " + outsb);
        if(0 < errsb.length())
            System.out.print("STDERR: " + errsb);
        System.out.println("Process exit code was: " + status);
        if(outsb.toString().contains("SSL handshake")) {
            System.out.println("!!! host " + host + " supports SSLv2");
        }
*/
    }

    private static SSLSocket createSSLSocket(InetSocketAddress address,
                                             String host,
                                             int port,
                                             int readTimeout,
                                             int connectTimeout,
                                             SSLSocketFactory sf)
        throws IOException
    {
        //
        // Note: SSLSocketFactory has several create() methods.
        // Those that take arguments all connect immediately
        // and have no options for specifying a connection timeout.
        //
        // So, we have to create a socket and connect it (with a
        // connection timeout), then have the SSLSocketFactory wrap
        // the already-connected socket.
        //
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);

        // Wrap plain socket in an SSL socket
        return (SSLSocket)sf.createSocket(sock, host, port, true);
    }

    private static String[] getJVMSupportedCipherSuites(String protocol, SecureRandom rand)
        throws NoSuchAlgorithmException, KeyManagementException
    {
        SSLContext sc = SSLContext.getInstance(protocol);

        sc.init(null, null, rand);

        return sc.getSocketFactory().getSupportedCipherSuites();
    }

    private static boolean checkTrust(X509Certificate[] chain, TrustManager[] trustManagers)
    {
        if(null == trustManagers)
            return false;

        if(1 == trustManagers.length
           && trustManagers[0] instanceof SSLUtils.TrustAllTrustManager)
            System.out.println("NOTE: Certificate chain will be trusted because all certificates are trusted");

        for(TrustManager tm : trustManagers) {
            if(tm instanceof X509TrustManager) {
                try {
                    ((X509TrustManager)tm).checkServerTrusted(chain, "RSA"); // TODO: Not always RSA?
                    return true;
                } catch (CertificateException ce) {
                    return false;
                }
            }
        }

        return false;
    }

    static final char[] hexChars = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f' };
    static String toHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for(byte b : bytes)
            sb.append(hexChars[(b >> 4) & 0x0f])
              .append(hexChars[b & 0x0f]);

        return sb.toString();
    }
}

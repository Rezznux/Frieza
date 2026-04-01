Java.perform(function () {
    function log(msg) {
        console.log("[unpin] " + msg);
    }

    // Trust all certificates via a custom TrustManager.
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "org.codex.InsecureTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        init.implementation = function (km, tm, sr) {
            log("SSLContext.init() hooked; replacing TrustManagers");
            init.call(this, km, TrustManagers, sr);
        };
    } catch (e) {
        log("SSLContext hook skipped: " + e);
    }

    // Hostname verification bypass.
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var HNV = Java.registerClass({
            name: "org.codex.InsecureHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        var setDefaultHostnameVerifier = HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
        setDefaultHostnameVerifier.implementation = function (verifier) {
            log("HttpsURLConnection.setDefaultHostnameVerifier() overridden");
            return setDefaultHostnameVerifier.call(this, HNV.$new());
        };
    } catch (e) {
        log("HostnameVerifier hook skipped: " + e);
    }

    // OkHttp3 CertificatePinner bypass.
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
            log("OkHttp3 CertificatePinner.check(host, list) bypass for " + hostname);
            return;
        };
        CertificatePinner.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (hostname, cert) {
            log("OkHttp3 CertificatePinner.check(host, cert) bypass for " + hostname);
            return;
        };
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
            log("OkHttp3 CertificatePinner.check(host, cert[]) bypass for " + hostname);
            return;
        };
    } catch (e) {
        log("OkHttp3 hook skipped: " + e);
    }

    // Android WebView SSL errors bypass.
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            log("WebViewClient.onReceivedSslError() bypass");
            handler.proceed();
        };
    } catch (e) {
        log("WebView hook skipped: " + e);
    }

    // TrustManagerImpl (Android >= 7) chain verification bypass.
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            log("TrustManagerImpl.verifyChain() bypass for host " + host);
            return untrustedChain;
        };
    } catch (e) {
        log("TrustManagerImpl hook skipped: " + e);
    }

    // Retrofit2 / OkHttp3 custom SSL socket factory bypass.
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClient.sslSocketFactory.overload(
            "javax.net.ssl.SSLSocketFactory",
            "javax.net.ssl.X509TrustManager"
        ).implementation = function (sf, tm) {
            log("OkHttpClient.Builder.sslSocketFactory() — replacing TrustManager");
            var X509TrustManager2 = Java.use("javax.net.ssl.X509TrustManager");
            var InsecureTM = Java.registerClass({
                name: "org.codex.InsecureTrustManager2",
                implements: [X509TrustManager2],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            return this.sslSocketFactory(sf, InsecureTM.$new());
        };
    } catch (e) {
        log("OkHttpClient.Builder.sslSocketFactory hook skipped: " + e);
    }

    // Apache HTTP client (legacy apps using DefaultHttpClient / SchemeRegistry).
    try {
        var SSLSocketFactory = Java.use("org.apache.http.conn.ssl.SSLSocketFactory");
        SSLSocketFactory.isSecure.implementation = function (socket) {
            log("Apache SSLSocketFactory.isSecure() → true");
            return true;
        };
    } catch (e) {
        log("Apache SSLSocketFactory hook skipped: " + e);
    }

    // Android Volley (uses HurlStack backed by HttpsURLConnection — already covered above via SSLContext,
    // but also patch the explicit verifier path used in some Volley builds).
    try {
        var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
        var HostnameVerifier2 = Java.use("javax.net.ssl.HostnameVerifier");
        var VolleyHNV = Java.registerClass({
            name: "org.codex.VolleyInsecureHNV",
            implements: [HostnameVerifier2],
            methods: { verify: function () { return true; } }
        });
        HurlStack.$init.overload("com.android.volley.toolbox.HurlStack$UrlRewriter", "javax.net.ssl.SSLSocketFactory").implementation = function (rewriter, sf) {
            log("HurlStack constructor patched — injecting permissive HostnameVerifier");
            this.$init(rewriter, sf);
            this.mSslSocketFactory.value = sf;
        };
    } catch (e) {
        log("Volley HurlStack hook skipped: " + e);
    }

    // Conscrypt / BoringSSL direct peer certificate check (some hardened apps call this directly).
    try {
        var OpenSSLSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
            log("OpenSSLSocketImpl.verifyCertificateChain() bypass");
        };
    } catch (e) {
        log("OpenSSLSocketImpl hook skipped: " + e);
    }

    log("Unpinning hooks installed");
});

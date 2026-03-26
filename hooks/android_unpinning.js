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

    log("Unpinning hooks installed");
});

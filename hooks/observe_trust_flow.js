Java.perform(function () {
    function log(msg) {
        console.log('[observe] ' + msg);
    }

    try {
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        var rbUrl = RequestBuilder.url.overload('java.lang.String');
        rbUrl.implementation = function (url) {
            log('Request URL: ' + url);
            return rbUrl.call(this, url);
        };
        log('okhttp3.Request$Builder.url hook enabled');
    } catch (e) {
        log('okhttp Request builder hook skipped: ' + e);
    }

    try {
        var Mac = Java.use('javax.crypto.Mac');
        var macGetInstance = Mac.getInstance.overload('java.lang.String');
        macGetInstance.implementation = function (algo) {
            log('Mac.getInstance: ' + algo);
            return macGetInstance.call(this, algo);
        };
        log('Mac.getInstance hook enabled');
    } catch (e) {
        log('Mac hook skipped: ' + e);
    }

    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        var mdGetInstance = MessageDigest.getInstance.overload('java.lang.String');
        mdGetInstance.implementation = function (algo) {
            log('MessageDigest.getInstance: ' + algo);
            return mdGetInstance.call(this, algo);
        };
        log('MessageDigest.getInstance hook enabled');
    } catch (e) {
        log('MessageDigest hook skipped: ' + e);
    }

    try {
        var PlayIntegrityMgrFactory = Java.use('com.google.android.play.core.integrity.IntegrityManagerFactory');
        var createMgr = PlayIntegrityMgrFactory.create;
        createMgr.implementation = function (ctx) {
            log('Play Integrity API used');
            return createMgr.call(this, ctx);
        };
        log('IntegrityManagerFactory hook enabled');
    } catch (e) {
        log('Play Integrity hook skipped: ' + e);
    }

    log('Trust-flow observation hooks installed');
});

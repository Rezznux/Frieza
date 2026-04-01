Java.perform(function () {
    function log(msg) {
        console.log('[attest] ' + msg);
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

    try {
        var SafetyNetClient = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
        var attest = SafetyNetClient.attest.overload('[B', 'java.lang.String');
        attest.implementation = function (nonce, apiKey) {
            log('SafetyNet attestation API used');
            return attest.call(this, nonce, apiKey);
        };
        log('SafetyNetClient.attest hook enabled');
    } catch (e) {
        log('SafetyNet hook skipped: ' + e);
    }

    log('Attestation-only observation hooks installed');
});

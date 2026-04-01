Java.perform(function () {
    function nowSeconds() {
        return Math.floor(Date.now() / 1000);
    }

    function emit(payload) {
        console.log('TRUST_E2E: ' + JSON.stringify(payload));
    }

    function log(msg) {
        console.log('[attest-cadence] ' + msg);
    }

    var lastSeen = 0;

    try {
        var IntegrityTokenRequestBuilder = Java.use('com.google.android.play.core.integrity.IntegrityTokenRequest$Builder');
        var setNonce = IntegrityTokenRequestBuilder.setNonce.overload('java.lang.String');
        setNonce.implementation = function (nonce) {
            var ts = nowSeconds();
            var delta = lastSeen === 0 ? 0 : (ts - lastSeen);
            lastSeen = ts;
            log('Integrity nonce observed; delta=' + delta + 's');
            emit({
                type: 'attest',
                observed_at_epoch: ts,
                cadence_seconds: delta,
                expected_nonce: nonce
            });
            return setNonce.call(this, nonce);
        };
        log('IntegrityTokenRequest.Builder.setNonce hook enabled');
    } catch (e) {
        log('IntegrityTokenRequest hook skipped: ' + e);
    }

    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
        var attest = SafetyNet.attest.overload('[B', 'java.lang.String');
        attest.implementation = function (nonce, apiKey) {
            var ts = nowSeconds();
            var delta = lastSeen === 0 ? 0 : (ts - lastSeen);
            lastSeen = ts;
            log('SafetyNet attest observed; delta=' + delta + 's');
            emit({
                type: 'attest',
                observed_at_epoch: ts,
                cadence_seconds: delta
            });
            return attest.call(this, nonce, apiKey);
        };
        log('SafetyNetClient.attest cadence hook enabled');
    } catch (e) {
        log('SafetyNet cadence hook skipped: ' + e);
    }
});

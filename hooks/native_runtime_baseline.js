function log(msg) {
    console.log('[native-baseline] ' + msg);
}

['dlopen', 'android_dlopen_ext'].forEach(function (symbol) {
    var address = Module.findExportByName(null, symbol);
    if (!address) {
        return;
    }
    Interceptor.attach(address, {
        onEnter: function (args) {
            try {
                log(symbol + ' -> ' + args[0].readCString());
            } catch (e) {
                log(symbol + ' observed');
            }
        }
    });
});

['ptrace', 'prctl', 'syscall', 'kill', 'tgkill', 'open', 'fopen', 'readlink'].forEach(function (symbol) {
    var address = Module.findExportByName(null, symbol);
    if (!address) {
        return;
    }
    Interceptor.attach(address, {
        onEnter: function () {
            log('native anti-tamper surface reached: ' + symbol);
        }
    });
});

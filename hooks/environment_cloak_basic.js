Java.perform(function () {
    function log(msg) {
        console.log("[envcloak] " + msg);
    }

    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        Build.FINGERPRINT.value = "google/redfin/redfin:13/TQ3A.230901.001/10750268:user/release-keys";
        Build.MODEL.value = "Pixel 5";
        Build.MANUFACTURER.value = "Google";
        log("Build fingerprint fields normalized");
    } catch (e) {
        log("Build cloaking skipped: " + e);
    }

    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () { return false; };
        Debug.waitingForDebugger.implementation = function () { return false; };
        log("Debugger state checks patched");
    } catch (e) {
        log("Debugger patch skipped: " + e);
    }

    try {
        var File = Java.use("java.io.File");
        var suspicious = [
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/magisk"
        ];
        var fileExists = File.exists.overload();
        fileExists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < suspicious.length; i++) {
                if (path === suspicious[i]) {
                    log("Hiding root artifact path " + path);
                    return false;
                }
            }
            return fileExists.call(this);
        };
        log("File.exists root artifact filter enabled");
    } catch (e) {
        log("File.exists hook skipped: " + e);
    }
});

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
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/bin/magisk",
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/proc/net/if_inet6",  // sometimes probed to detect emulator
        ];
        var fileExists = File.exists.overload();
        fileExists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < suspicious.length; i++) {
                if (path === suspicious[i]) {
                    log("Hiding root artifact: " + path);
                    return false;
                }
            }
            return fileExists.call(this);
        };
        log("File.exists root artifact filter enabled");
    } catch (e) {
        log("File.exists hook skipped: " + e);
    }

    // Spoof SystemProperties used by emulator/root detection.
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var SPOOF_PROPS = {
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.build.tags": "release-keys",
            "ro.build.type": "user",
        };
        var getPropStr = SystemProperties.get.overload("java.lang.String");
        getPropStr.implementation = function (key) {
            if (SPOOF_PROPS[key] !== undefined) {
                log("Spoofing SystemProperties.get(" + key + ")");
                return SPOOF_PROPS[key];
            }
            return getPropStr.call(this, key);
        };
        var getPropDefault = SystemProperties.get.overload("java.lang.String", "java.lang.String");
        getPropDefault.implementation = function (key, def) {
            if (SPOOF_PROPS[key] !== undefined) {
                log("Spoofing SystemProperties.get(" + key + ", def)");
                return SPOOF_PROPS[key];
            }
            return getPropDefault.call(this, key, def);
        };
        log("SystemProperties ro.debuggable/ro.secure/ro.build.tags/type spoofed");
    } catch (e) {
        log("SystemProperties hook skipped: " + e);
    }
});

Java.perform(function () {
    function log(msg) {
        console.log("[antidetect] " + msg);
    }

    // Prevent basic debugger checks.
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () { return false; };
        Debug.waitingForDebugger.implementation = function () { return false; };
        log("android.os.Debug checks neutralized");
    } catch (e) {
        log("Debug checks skipped: " + e);
    }

    // Suppress common process execution probes for Frida/root indicators.
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var overload = Runtime.exec.overload("[Ljava.lang.String;");
        overload.implementation = function (cmd) {
            var joined = cmd.join(" ").toLowerCase();
            if (joined.indexOf("frida") !== -1 || joined.indexOf("su") !== -1 || joined.indexOf("magisk") !== -1) {
                log("Blocking suspicious Runtime.exec probe: " + joined);
                return overload.call(this, ["sh", "-c", "echo"]);
            }
            return overload.call(this, cmd);
        };
        log("Runtime.exec probe filter enabled");
    } catch (e) {
        log("Runtime.exec hook skipped: " + e);
    }

    // Hide tracer/debug flags and Frida artifacts from Java-level /proc reads.
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        var readLine = BufferedReader.readLine.overload();
        var FRIDA_STRINGS = ["frida", "gum-js-loop", "gmain", "linjector", "re.frida"];
        readLine.implementation = function () {
            var line = readLine.call(this);
            if (line === null) return null;
            if (line.indexOf("TracerPid:") === 0) {
                log("Masking TracerPid line");
                return "TracerPid:\t0";
            }
            var lower = line.toLowerCase();
            for (var i = 0; i < FRIDA_STRINGS.length; i++) {
                if (lower.indexOf(FRIDA_STRINGS[i]) !== -1) {
                    log("Masking /proc line containing: " + FRIDA_STRINGS[i]);
                    return "";
                }
            }
            return line;
        };
        log("TracerPid + /proc maps masking enabled");
    } catch (e) {
        log("BufferedReader mask skipped: " + e);
    }

    // Suppress Xposed/LSPosed detection via Class.forName probe.
    try {
        var ClassLoader = Java.use("java.lang.Class");
        var forName = ClassLoader.forName.overload("java.lang.String");
        var XPOSED_CLASSES = ["de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XC_MethodHook", "io.github.lsposed.lspd"];
        forName.implementation = function (name) {
            for (var i = 0; i < XPOSED_CLASSES.length; i++) {
                if (name.indexOf(XPOSED_CLASSES[i]) === 0) {
                    log("Blocking Xposed probe for: " + name);
                    throw Java.use("java.lang.ClassNotFoundException").$new(name);
                }
            }
            return forName.call(this, name);
        };
        log("Xposed class probe suppressed");
    } catch (e) {
        log("Class.forName hook skipped: " + e);
    }

    // Suppress ActivityManager.getRunningAppProcesses() process-name inspection.
    try {
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getRunningAppProcesses.implementation = function () {
            var procs = this.getRunningAppProcesses();
            if (procs === null) return procs;
            var ArrayList = Java.use("java.util.ArrayList");
            var filtered = ArrayList.$new();
            var iter = procs.iterator();
            while (iter.hasNext()) {
                var proc = iter.next();
                var pname = proc.processName.value.toLowerCase();
                if (pname.indexOf("frida") === -1 && pname.indexOf("magisk") === -1) {
                    filtered.add(proc);
                } else {
                    log("Hiding suspicious process: " + pname);
                }
            }
            return filtered;
        };
        log("ActivityManager.getRunningAppProcesses() filter enabled");
    } catch (e) {
        log("ActivityManager hook skipped: " + e);
    }
});

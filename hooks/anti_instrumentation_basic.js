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

    // Hide tracer/debug flags from Java-level /proc reads.
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        var readLine = BufferedReader.readLine.overload();
        readLine.implementation = function () {
            var line = readLine.call(this);
            if (line !== null && line.indexOf("TracerPid:") === 0) {
                return "TracerPid:\t0";
            }
            return line;
        };
        log("TracerPid masking enabled");
    } catch (e) {
        log("BufferedReader TracerPid mask skipped: " + e);
    }
});

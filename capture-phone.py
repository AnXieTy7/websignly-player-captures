#!/usr/bin/env python3
"""Generic public-APK-only native phone captures. No private source or keys."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zlib

APK_URL = "https://websignly.com/downloads/websignly.apk"
APK_SHA256 = "8d5f58b6d3b25995bb76ad85492980fa1c180fb99f47a2c0f6960602736abe25"
APK_BYTES = 1535724
CERT = "9883d1be43f1cac101668091fb5796ad261b04b5ad2abb1de81cd43fbe78aa05"
PACKAGE = "com.websignly.player"
COMPONENT = PACKAGE + "/.MainActivity"
CATALOG = "https://dl.google.com/android/repository/repository2-3.xml"
PHONE_CATALOG = "https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-5.xml"
IMAGE = "system-images;android-36;google_apis;x86_64"
METADATA = {"emulator": "emulator/package.xml", IMAGE: "system-images/android-36/google_apis/x86_64/package.xml"}
LICENSE = "1f8729233617b193fd619213792ae16a41b95d2bbbf525dfe66998252ba68b16"
SDK_LICENSE_SHA1 = "24333f8a63b6825ea9c5514f83c2829b004d1fee"
W, H = 1080, 1920
SERIAL, PORT = "emulator-5556", "5038"
AVD_NAME = "PublicPhoneCapture"
BOOT_LIMIT = 16384
BOOT_OMISSION = b"\n[bounded startup output: middle omitted]\n"


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def safe_error(error):
    code = str(error) if isinstance(error, Refused) else "CAPTURE_OPERATION_FAILED"
    value = {"error": code if re.fullmatch(r"[A-Z0-9_]{1,80}", code) else "CAPTURE_OPERATION_FAILED",
             "exceptionType": type(error).__name__}
    if isinstance(error, OSError) and type(error.errno) is int:
        value["errno"] = error.errno
    if type(getattr(error, "exit_code", None)) is int:
        value["commandExitCode"] = error.exit_code
    if getattr(error, "operation_phase", None) in {"license_backup", "license_setup", "sdk_command"}:
        value["operationPhase"] = error.operation_phase
    if getattr(error, "sdk_diagnostic", None) in {"SDK_LICENSE_NOT_ACCEPTED", "SDK_JAVA_HOME_INVALID", "SDK_JAVA_VERSION_INVALID", "SDK_PACKAGE_UNAVAILABLE", "SDK_INSTALL_PERMISSIONS", "SDK_INSTALL_OTHER"}:
        value["sdkDiagnostic"] = error.sdk_diagnostic
    if getattr(error, "cleanup_errors", None):
        value["cleanupErrors"] = error.cleanup_errors
    if getattr(error, "sdk_package", None) in METADATA:
        value["sdkPackage"] = error.sdk_package
        value["expectedMetadata"] = METADATA[error.sdk_package]
        if type(getattr(error, "source_properties_exists", None)) is bool:
            value["sourcePropertiesExists"] = error.source_properties_exists
    return value


def sdk_diagnostic(output):
    text = output.decode("utf-8", errors="replace").lower()
    if "license" in text and any(term in text for term in ("not accepted", "not been accepted", "accept the sdk license", "review licenses")):
        return "SDK_LICENSE_NOT_ACCEPTED"
    if "java_home" in text and any(term in text for term in ("not set", "invalid", "not found")):
        return "SDK_JAVA_HOME_INVALID"
    if "unsupportedclassversionerror" in text or "java version 17 or higher is required" in text:
        return "SDK_JAVA_VERSION_INVALID"
    if "failed to find package" in text or "package path is not valid" in text:
        return "SDK_PACKAGE_UNAVAILABLE"
    if "permission denied" in text or "failed to read or create install properties" in text:
        return "SDK_INSTALL_PERMISSIONS"
    return "SDK_INSTALL_OTHER"


def sdk_summary(output):
    # Fixed markers only: never publish SDK stdout or its untrusted paths/URLs.
    text = output[-65536:].decode("utf-8", errors="replace").lower()
    markers = []
    for marker, match in (("SDK_XML_VERSION_WARNING", "sdk xml" in text and "version" in text),
                          ("SDK_PACKAGE_LAYOUT_WARNING", "observed package id" in text and "inconsistent location" in text),
                          ("SDK_INSTALL_PROPERTIES_WARNING", "failed to read or create install properties" in text),
                          ("SDK_LICENSE_PROMPT", "review licenses" in text or "accept? (y/n)" in text)):
        if match:
            markers.append(marker)
    return markers


def boot_output(data):
    """Bound and redact official emulator startup output; never app/device logcat."""
    if len(data) > BOOT_LIMIT:
        part = (BOOT_LIMIT - len(BOOT_OMISSION)) // 2
        data = data[:part] + BOOT_OMISSION + data[-part:]
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", "?", text)
    text = re.sub(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "<redacted-jwt>", text)
    text = re.sub(r"(?i)\b(?:[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}|[a-f0-9]{32,})\b", "<redacted-id>", text)
    text = re.sub(r"(?i)\b(?:[a-f0-9]{2}:){5}[a-f0-9]{2}\b", "<redacted-mac>", text)
    text = re.sub(r"(?i)\bbearer\s+\S+", "Bearer <redacted>", text)
    text = re.sub(r"(?i)\b((?:(?:access|refresh|id|api|auth|session|private)[_-]?)?(?:token|key)|authorization|password|secret)\s*[:=]\s*\S+", r"\1=<redacted>", text)
    text = re.sub(r"\b(?:AIza[A-Za-z0-9_-]{25,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_-]+)\b", "<redacted-key>", text)
    text = re.sub(r"\b[A-Za-z0-9_-]{32,}\b", "<redacted-id>", text)
    text = re.sub(r"https?://[^\s\"'<>]+", "<url>", text)
    text = re.sub(r"(?<!\w)/(?:home|usr|opt|tmp|var|dev|proc|sys|etc|run)(?:/[^\s\"'<>]+)*", "<path>", text)
    text = re.sub(r"[A-Za-z]:[\\/][^\s\"'<>]+", "<path>", text)
    return text.encode("utf-8")[:BOOT_LIMIT].decode("utf-8", errors="ignore")


def boot_classifications(data):
    text = data[-131072:].decode("utf-8", errors="replace").lower()
    patterns = {"BOOT_DISK_SPACE": r"not enough disk space|no space left on device|insufficient.*disk",
                "BOOT_CLI_OPTION": r"unknown option|invalid command.line option|invalid value for -gpu",
                "BOOT_GPU_INIT": r"failed to.*vulkan|failed to.*egl|gpu.*initialization.*fail|invalid gpu mode",
                "BOOT_HOST_DISPLAY": r"could not initialize sdl|qt platform plugin|could not load.*xcb|libx11.*not found",
                "BOOT_KVM": r"failed to initialize kvm|kvm.*permission denied|requires hardware acceleration",
                "BOOT_AVD_PATH": r"broken avd system path|unknown avd name|cannot find avd system path",
                "BOOT_ADB": r"failed to connect to adb|unable to connect to adb daemon",
                "BOOT_CRASH": r"segmentation fault|sigsegv|fatal signal 11"}
    return [code for code, pattern in patterns.items() if re.search(pattern, text)] or ["BOOT_REASON_UNCLASSIFIED"]


def disk_free(sdk, state):
    result = {}
    for name, path in (("sdk", sdk), ("state", state)):
        try:
            result[name] = shutil.disk_usage(path).free
        except OSError:
            result[name] = None
    return result


def can_retain_boot(status, apk_install_started, organization_paired, process_started, emulator_stopped):
    return status == "failed" and not apk_install_started and not organization_paired and process_started and emulator_stopped


def create_avd_roots(state):
    # The SDK's PathLocator ignores ANDROID_AVD_HOME unless it already exists.
    # Make it before the first SDK process can cache a fallback registry path.
    need(state.is_dir() and not state.is_symlink(), "AVD_STATE_INVALID")
    avd_home, user_home = state / "avd", state / "android-user"
    avd_home.mkdir(mode=0o700)
    user_home.mkdir(mode=0o700)
    return avd_home, user_home


def read_avd_ini(path):
    need(path.is_file() and not path.is_symlink(), "AVD_METADATA_MISSING")
    need(path.stat().st_size <= 65536, "AVD_METADATA_TOO_LARGE")
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        need("=" in line, "AVD_METADATA_INVALID")
        key, value = [piece.strip() for piece in line.split("=", 1)]
        need(key and key not in values and "\0" not in value, "AVD_METADATA_INVALID")
        values[key] = value
    return values


def validate_avd(state, avd_home, avd_data, sdk):
    root = state.resolve()
    need(avd_home.resolve().parent == root and avd_data.resolve().parent == avd_home.resolve()
         and not avd_home.is_symlink() and not avd_data.is_symlink(), "AVD_STATE_PATH_MISMATCH")
    index_path = avd_home / (AVD_NAME + ".ini")
    need(index_path.is_file(), "AVD_REGISTRY_INDEX_MISSING")
    index = read_avd_ini(index_path)
    need("path" in index and Path(index["path"]).is_absolute() and Path(index["path"]).resolve() == avd_data.resolve(), "AVD_REGISTRY_PATH_MISMATCH")
    config = read_avd_ini(avd_data / "config.ini")
    need(config.get("abi.type") == "x86_64" and config.get("hw.cpu.arch") == "x86_64" and config.get("tag.id") == "google_apis", "AVD_IMAGE_IDENTITY_MISMATCH")
    need(not any(key.startswith("image.sysdir.") and key != "image.sysdir.1" for key in config), "AVD_IMAGE_PATH_MISMATCH")
    image = Path(config.get("image.sysdir.1", ""))
    image = image if image.is_absolute() else sdk / image
    need(image.resolve() == (sdk / "system-images/android-36/google_apis/x86_64").resolve(), "AVD_IMAGE_PATH_MISMATCH")
    need(config.get("AvdId", AVD_NAME) == AVD_NAME, "AVD_NAME_MISMATCH")
    return {"registryIndexPresent": True, "registryPathMatches": True, "dataInsideOwnedState": True,
            "configImageMatches": True, "api": 36, "abi": "x86_64"}


def check_sdk_result(exit_code, output):
    diagnostic = sdk_diagnostic(output)
    if exit_code != 0 or diagnostic != "SDK_INSTALL_OTHER":
        error = Refused("SDK_INSTALL_FAILED")
        error.exit_code, error.sdk_diagnostic = exit_code, diagnostic
        raise error
    return sdk_summary(output)


def inspect_installed(sdk, package, wanted):
    need(package in METADATA, "INSTALLED_SDK_PACKAGE_UNEXPECTED")
    manifest = sdk / METADATA[package]
    try:
        if not manifest.is_file():
            raise Refused("INSTALLED_SDK_METADATA_MISSING")
        need(manifest.stat().st_size <= 1024**2, "INSTALLED_SDK_METADATA_TOO_LARGE")
        root = ET.fromstring(manifest.read_bytes())
        matches = [n for n in root if tag(n) == "localPackage" and n.get("path") == package]
        need(len(matches) == 1 and revision(child(matches[0], "revision")) == wanted, "INSTALLED_SDK_CHANGED")
    except Exception as error:
        error.sdk_package = package
        try:
            error.source_properties_exists = (manifest.parent / "source.properties").is_file()
        except OSError:
            pass  # Optional diagnostics must not replace the metadata failure.
        raise


def with_reviewed_licenses(sdk, state, hashes, operation):
    """Restore runner licenses without masking an install failure or deleting SDK-created files."""
    license_dir = sdk / "licenses"
    token = uuid.uuid4().hex
    # SDK and RUNNER_TEMP may be different filesystems. Adjacent siblings keep
    # every rename atomic on the SDK filesystem, including error restoration.
    backup = sdk / (".phone-capture-license-backup-" + token)
    quarantine = sdk / (".phone-capture-license-state-" + token)
    created, primary = False, None
    phase = "license_backup"
    need(not any(p.exists() or p.is_symlink() for p in (backup, quarantine)), "LICENSE_RESTORE_STATE_ALREADY_EXISTS")
    try:
        if license_dir.exists():
            license_dir.rename(backup)
        phase = "license_setup"
        license_dir.mkdir()
        created = True
        (license_dir / "android-sdk-license").write_text("\n".join(sorted(hashes)) + "\n")
        phase = "sdk_command"
        return operation()
    except BaseException as error:
        error.operation_phase = phase
        primary = error
        raise
    finally:
        failures = []
        try:
            # SDKmanager can create additional files here. Preserve the entire
            # generated directory outside its accepted-license location rather
            # than rmdir(), which would replace the primary failure with ENOTEMPTY.
            if created and license_dir.exists():
                license_dir.rename(quarantine)
        except Exception as error:
            failures.append(safe_error(error))
        try:
            if backup.exists():
                need(not license_dir.exists(), "SDK_LICENSE_RESTORE_PATH_OCCUPIED")
                backup.rename(license_dir)
        except Exception as error:
            failures.append(safe_error(error))
        if failures:
            if primary is not None:
                primary.cleanup_errors = failures
            else:
                error = Refused("SDK_LICENSE_RESTORE_FAILED")
                error.cleanup_errors = failures
                raise error


def tag(node):
    return node.tag.rsplit("}", 1)[-1]


def child(node, name):
    return next((n for n in node if tag(n) == name), None)


def revision(node):
    need(node is not None, "SDK_REVISION_MISSING")
    return [int(child(node, n).text) if child(node, n) is not None else 0 for n in ("major", "minor", "micro")]


def normalized_license(value):
    # Exact SDK TrimStringAdapter.unmarshal sequence, verified against the
    # actual SDK class. Java's default regex \s and String.trim are ASCII here.
    value = re.sub(r"(?<=\s)[ \t]*", "", value, flags=re.ASCII)
    value = re.sub(r"(?<!\n)\n(?!\n)", " ", value)
    value = re.sub(r" +", " ", value)
    return value.strip("".join(chr(code) for code in range(0x21)))


def validate_pins(pins):
    need(pins.get("reviewed") is True, "PHONE_METADATA_REVIEW_PENDING")
    need(pins.get("image") == IMAGE and pins.get("phoneCatalogUrl") == PHONE_CATALOG and pins.get("licenseSha256") == LICENSE,
         "SDK_PIN_IDENTITY_INVALID")
    for key in ("imageRevision", "emulatorRevision"):
        need(isinstance(pins.get(key), list) and len(pins[key]) == 3 and all(type(n) is int and n >= 0 for n in pins[key]), "SDK_PIN_REVISION_INVALID")
    need(isinstance(pins.get("imageDependencies"), dict), "SDK_PIN_DEPENDENCIES_INVALID")
    for key in ("imageArchive", "emulatorArchive"):
        value = pins.get(key)
        need(isinstance(value, dict) and re.fullmatch(r"[A-Za-z0-9_.-]+\.zip", value.get("url", ""))
             and type(value.get("size")) is int and 0 < value["size"] <= 3 * 1024**3
             and re.fullmatch(r"[a-f0-9]{40}", value.get("sha1", "")), "SDK_PIN_ARCHIVE_INVALID")


def inspect_catalog(data, package, wanted, archive, dependencies, *, expected_license=LICENSE):
    need(len(data) <= 8 * 1024**2, "SDK_CATALOG_TOO_LARGE")
    root = ET.fromstring(data)
    matches = [n for n in root if tag(n) == "remotePackage" and n.get("path") == package
               and child(n, "channelRef") is not None and child(n, "channelRef").get("ref") == "channel-0"]
    need(len(matches) == 1, "SDK_PACKAGE_CHANGED")
    node = matches[0]
    need(revision(child(node, "revision")) == wanted and node.get("obsolete") != "true", "SDK_REVISION_CHANGED")
    deps = child(node, "dependencies")
    actual = {n.get("path"): revision(child(n, "min-revision")) for n in deps} if deps is not None else {}
    need(actual == dependencies, "SDK_DEPENDENCIES_CHANGED")
    license_ref = child(node, "uses-license")
    need(license_ref is not None and license_ref.get("ref") == "android-sdk-license", "SDK_LICENSE_ID_CHANGED")
    terms = [n.text for n in root if tag(n) == "license" and n.get("id") == "android-sdk-license"]
    need(len(terms) == 1 and hashlib.sha256(terms[0].encode()).hexdigest() == expected_license, "SDK_LICENSE_CHANGED")
    # Check reviewed raw terms FIRST; canonicalization changes storage format,
    # never which agreement is accepted. Synthetic terms are unit fixtures only.
    canonical_hash = hashlib.sha1(normalized_license(terms[0]).encode()).hexdigest()
    if expected_license == LICENSE:
        need(canonical_hash == SDK_LICENSE_SHA1, "SDK_LICENSE_CANONICAL_HASH_CHANGED")
    candidates = []
    for entry in child(node, "archives"):
        host = child(entry, "host-os")
        if host is None or host.text == "linux":
            full = child(entry, "complete")
            checksum = child(full, "checksum")
            need(checksum is not None and checksum.get("type") == "sha1", "SDK_CHECKSUM_ALGORITHM_CHANGED")
            candidates.append({"url": child(full, "url").text, "size": int(child(full, "size").text), "sha1": checksum.text})
    need(len(candidates) == 1 and candidates[0] == archive, "SDK_ARCHIVE_CHANGED")
    return {canonical_hash}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_a, **_kw):
        raise Refused("DOWNLOAD_REDIRECT_REFUSED")


def fetch(url, maximum):
    need(url in (APK_URL, CATALOG, PHONE_CATALOG), "DOWNLOAD_ORIGIN_REFUSED")
    with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers={"User-Agent": "NativePhoneCapture/1"}), timeout=30) as response:
        need(response.status == 200, "DOWNLOAD_STATUS_INVALID")
        data = response.read(maximum + 1)
    need(len(data) <= maximum, "DOWNLOAD_TOO_LARGE")
    return data


def ui(data):
    need(len(data) <= 2 * 1024**2, "UI_DUMP_TOO_LARGE")
    nodes = [n for n in ET.fromstring(data).iter("node") if n.get("package") == PACKAGE]
    need(nodes, "NATIVE_UI_MISSING")
    return nodes


def pairing(data):
    values = [n.get("text", "") for n in ui(data)]
    return any(re.fullmatch(r"[0-9]{6}", t) for t in values) and any("Your next great screen" in t for t in values)


def settings(data):
    values = [n.get("text", "") for n in ui(data)]
    return ("PLAYER SETTINGS" in values and "Privacy policy" in values
            and any("Ready to pair" in t and "Active revision: none" in t for t in values)
            and not any("Unpair and remove local content" in t for t in values))


def transition_wait(read, check, observe, seconds=20, clock=time.monotonic, pause=time.sleep):
    deadline = clock() + seconds
    last = b"<hierarchy/>"
    while clock() < deadline:
        last = read()
        try:
            if check(last):
                observed = observe(last, True)
                if isinstance(observed, dict) and observed.get("observedSurfaceDismissed"):
                    pause(.3)
                    continue
                return last
        except Refused as error:
            if str(error) != "NATIVE_UI_MISSING":
                raise
        observe(last, True)
        pause(.3)
    observe(last, False)
    raise Refused("UI_TRANSITION_TIMEOUT")


def verified_capture_sample(read, grab, check, observe, seconds=20, clock=time.monotonic, pause=time.sleep):
    deadline = clock() + seconds
    def scene():
        data = read()
        try:
            valid = check(data)
        except Refused as error:
            if str(error) != "NATIVE_UI_MISSING":
                raise
            valid = None
        snapshot = observe(data, True)
        need(snapshot and snapshot["ownedForeground"] and snapshot["nativePidPresent"], "CAPTURE_OWNERSHIP_UNVERIFIED")
        if snapshot.get("observedSurfaceDismissed") or snapshot.get("immersiveWindowPresent") or valid is None:
            return None
        need(valid, "CAPTURE_UI_INVALID")
        need(set(snapshot["packages"]) == {PACKAGE}, "CAPTURE_UNKNOWN_OVERLAY")
        return data
    while clock() < deadline:
        if scene() is None:
            pause(.3)
            continue
        need(clock() < deadline, "CAPTURE_TRANSIENT_TIMEOUT")
        pixels = grab()
        after = scene()
        if after is None:
            pause(.3)
            continue  # Never save pixels sampled while a recognized overlay appeared.
        need(clock() < deadline, "CAPTURE_TRANSIENT_TIMEOUT")
        return pixels, after
    raise Refused("CAPTURE_TRANSIENT_TIMEOUT")


def ui_diagnostics(data, input_method, owned_foreground, native_pid):
    root = ET.fromstring(data)
    packages = sorted({n.get("package", "") for n in root.iter("node")
                       if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", n.get("package", ""))})[:16]
    shown = bool(re.search(r"(?:mInputShown|isInputShown)\s*=\s*true\b", input_method))
    visible = (bool(re.search(r"mIsInputViewShown\s*=\s*true\b", input_method)) or
               any(int(value, 16) & 2 for value in re.findall(r"mImeWindowVis\s*=\s*0x([0-9a-fA-F]+)", input_method)))
    allowed_labels = ("PLAYER SETTINGS", "Privacy policy", "Ready to pair", "Active revision: none", "Proof events waiting: 0", "WebSignly privacy policy", "Close", "CLOSE")
    labels = sorted({label for n in root.iter("node") if n.get("package") == PACKAGE
                     for label in allowed_labels if label in n.get("text", "")})
    ime_packages = sorted(set(re.findall(r"(?:mCurId|mCurMethodId)\s*=\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/", input_method)))[:4]
    return {"ownedForeground": owned_foreground, "nativePidPresent": native_pid,
            "imeShown": shown, "imeVisible": visible, "imePackages": ime_packages, "packages": packages, "ownLabels": labels}


def window_diagnostics(policy, windows):
    block = policy.split("KeyguardServiceDelegate", 1)[-1] if "KeyguardServiceDelegate" in policy else ""
    result = {"immersiveWindowPresent": "ImmersiveModeConfirmation" in windows}
    for field in ("showing", "inputRestricted", "occluded", "secure"):
        match = re.search(r"(?m)^\s*" + field + r"\s*=\s*(true|false)\b", block)
        result["keyguard" + field[0].upper() + field[1:]] = None if match is None else match.group(1) == "true"
    return result


def fullscreen_help_target(data, snapshot):
    if not snapshot["ownedForeground"] or not snapshot["nativePidPresent"] or snapshot.get("keyguardShowing") is True or snapshot.get("keyguardSecure") is True:
        return None
    nodes = [n for n in ET.fromstring(data).iter("node") if n.get("package") == "com.android.systemui"]
    if not nodes or any(n.get("password") == "true" for n in nodes):
        return None
    title = any("Viewing full screen" in (n.get("text", ""), n.get("content-desc", "")) for n in nodes)
    description = any(n.get("resource-id") == "com.android.systemui:id/immersive_cling_description"
                      and n.get("text") == "To exit, swipe down from the top of your screen" for n in nodes)
    buttons = [n for n in nodes if n.get("resource-id") == "com.android.systemui:id/ok" and n.get("text") == "Got it"
               and n.get("class") == "android.widget.Button" and n.get("clickable") == "true" and n.get("enabled") == "true"]
    if not description or not (title or snapshot.get("immersiveWindowPresent") is True) or len(buttons) != 1:
        return None
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", buttons[0].get("bounds", ""))
    if not match:
        return None
    x1, y1, x2, y2 = map(int, match.groups())
    return ((x1+x2)//2, (y1+y2)//2) if 0 <= x1 < x2 <= W and 0 <= y1 < y2 <= H else None


def can_dismiss_nonsecure_keyguard(snapshot):
    return snapshot.get("keyguardShowing") is True and snapshot.get("keyguardSecure") is False


def can_hide_ime(snapshot, phase):
    keyboards = {"com.google.android.inputmethod.latin", "com.android.inputmethod.latin"}
    return (phase in {"SETTINGS_TRANSITION", "PRIVACY_TRANSITION"} and snapshot["ownedForeground"]
            and snapshot["nativePidPresent"] and snapshot["imeShown"] and snapshot["imeVisible"]
            and bool(keyboards.intersection(snapshot["packages"] + snapshot["imePackages"])))


def can_retain_ui(snapshot, unpaired_flow, organization_paired):
    allowed = {PACKAGE, "android", "com.android.systemui", "com.google.android.inputmethod.latin", "com.android.inputmethod.latin"}
    return (unpaired_flow and not organization_paired and snapshot["ownedForeground"]
            and snapshot["nativePidPresent"] and bool(snapshot["packages"])
            and set(snapshot["packages"]).issubset(allowed))


def label_matches(actual, expected):
    # API36 native Button styling exposes the observed uppercase CLOSE label.
    # Keep all other labels exact and accept only these two known forms.
    return actual == expected or (expected == "Close" and actual == "CLOSE")


def privacy(data):
    values = [n.get("text", "") for n in ui(data)]
    return "WebSignly privacy policy" in values and any("WebOrbit LLC" in t for t in values) and any(label_matches(t, "Close") for t in values) and not any("Loading privacy policy" in t for t in values)


def foreground(value):
    return any("ResumedActivity" in line and re.search(r"com\.websignly\.player/(?:\.MainActivity|com\.websignly\.player\.MainActivity)(?=[\s}])", line) for line in value.splitlines())


def png_rgb(data, width=W, height=H):
    need(len(data) <= 12 * 1024**2 and data[:8] == b"\x89PNG\r\n\x1a\n", "CAPTURE_NOT_PNG")
    offset, compressed, channels, done = 8, bytearray(), None, False
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        kind, body = data[offset + 4:offset + 8], data[offset + 8:offset + 8 + length]
        need(length <= 12 * 1024**2 and offset + length + 12 <= len(data), "PNG_TRUNCATED")
        need(zlib.crc32(kind + body) & 0xffffffff == struct.unpack_from(">I", data, offset + length + 8)[0], "PNG_CRC_INVALID")
        if kind == b"IHDR":
            need(channels is None and len(body) == 13, "PNG_HEADER_INVALID")
            actual_w, actual_h, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
            need((actual_w, actual_h, depth, colour, compression, filtering, interlace) in [(width, height, 8, c, 0, 0, 0) for c in (2, 6)], "PNG_DIMENSIONS_INVALID")
            channels = 3 if colour == 2 else 4
        elif kind == b"IDAT":
            compressed.extend(body)
        elif kind == b"IEND":
            need(length == 0, "PNG_END_INVALID")
            done = True
        offset += length + 12
        if done:
            break
    need(channels is not None and done and offset == len(data), "PNG_INCOMPLETE")
    size = height * (width * channels + 1)
    decoder = zlib.decompressobj()
    packed = decoder.decompress(compressed, size + 1)
    need(decoder.eof and not decoder.unused_data and len(packed) == size, "PNG_PIXELS_INVALID")
    previous, rgb, values = bytearray(width * channels), bytearray(), set()
    for y in range(height):
        begin = y * (width * channels + 1)
        method, row = packed[begin], bytearray(packed[begin + 1:begin + width * channels + 1])
        need(method <= 4, "PNG_FILTER_INVALID")
        for x in range(len(row)):
            left = row[x - channels] if x >= channels else 0
            up, corner = previous[x], previous[x - channels] if x >= channels else 0
            estimate = left + up - corner
            distances = [abs(estimate - n) for n in (left, up, corner)]
            paeth = (left, up, corner)[distances.index(min(distances))]
            row[x] = (row[x] + (0, left, up, (left + up) // 2, paeth)[method]) & 255
        need(channels == 3 or all(row[x] == 255 for x in range(3, len(row), 4)), "PNG_TRANSLUCENT_REFUSED")
        visible = row if channels == 3 else bytearray(v for x, v in enumerate(row) if x % 4 != 3)
        values.update(visible)
        rgb.extend(b"\0" + visible)
        previous = row
    need(len(values) > 16, "CAPTURE_BLANK")
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rgb, 6)) + chunk(b"IEND", b"")


def run(pins):
    validate_pins(pins)  # Refuse incomplete review before even catalog network access.
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and os.environ.get("PHONE_CAPTURE_APPROVED") == "true" and os.environ.get("PUBLIC_STANDARD_RUNNER_VERIFIED") == "true", "MANUAL_PUBLIC_WORKFLOW_REQUIRED")
    need((os.cpu_count() or 0) >= 4 and os.access("/dev/kvm", os.R_OK | os.W_OK), "FREE_KVM_RUNNER_REQUIRED")
    sdk = Path(os.environ.get("ANDROID_HOME", "")).resolve()
    need(sdk == Path("/usr/local/lib/android/sdk"), "RUNNER_SDK_UNEXPECTED")
    temporary = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
    need(str(temporary).startswith("/home/runner/work/") and temporary.is_dir(), "RUNNER_TEMP_UNEXPECTED")
    state = temporary / "public-apk-phone-capture"
    need(not state.exists(), "STATE_ALREADY_EXISTS")
    state.mkdir(mode=0o700)
    artifacts = state / "artifacts"
    artifacts.mkdir(mode=0o700)
    (artifacts / "raw").mkdir(mode=0o700)
    avd_home, user_home = create_avd_roots(state)
    avd_data = avd_home / (AVD_NAME + ".avd")
    deadline, started, process, stage = time.monotonic() + 18 * 60, time.monotonic(), None, "preflight"
    adb_started, apk_install_started = False, False
    unpaired_flow, ime_hidden, last_observation = False, False, 0.0
    fullscreen_acknowledged, keyguard_dismissed = False, False
    ui_phase, last_ui_data, last_ui_snapshot = "PAIRING_WAIT", b"<hierarchy/>", None
    env = {**os.environ, "ANDROID_AVD_HOME": str(avd_home), "ANDROID_USER_HOME": str(user_home), "ANDROID_ADB_SERVER_PORT": PORT}
    evidence = {"status": "running", "distribution": "public standalone APK; pairing/privacy shared, settings channel may differ", "phoneImage": IMAGE,
                "apkSha256": APK_SHA256, "organizationPaired": False, "playStoreInstallVerified": False, "captures": []}
    stage_history = [stage]
    evidence["uiStageHistory"] = [ui_phase]
    def command(args, code, seconds=60, data=None):
        nonlocal stage
        stage = code
        stage_history.append(stage)
        remaining = min(seconds, int(deadline - time.monotonic()))
        need(remaining > 0, "TIME_BUDGET_EXHAUSTED")
        with (state / "command.log").open("wb") as stream:
            result = subprocess.run([str(a) for a in args], input=data, stdin=subprocess.DEVNULL if data is None else None, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=remaining, cwd=state, env=env)
        need((state / "command.log").stat().st_size <= 8 * 1024**2, "COMMAND_OUTPUT_TOO_LARGE")
        output = (state / "command.log").read_bytes()
        if code == "SDK_INSTALL_FAILED":
            evidence["sdkCommandExitCode"] = result.returncode
            evidence["sdkWarningCodes"] = sdk_summary(output)
            check_sdk_result(result.returncode, output)
        if result.returncode != 0:
            error = Refused(code)
            error.exit_code = result.returncode
            raise error
        return output
    adb = sdk / "platform-tools/adb"
    tools = sdk / "build-tools/35.0.0"
    manager, avd = [sdk / ("cmdline-tools/latest/bin/" + n) for n in ("sdkmanager", "avdmanager")]
    def device(*args, seconds=30):
        return command([adb, "-P", PORT, "-s", SERIAL, *args], "ADB_OPERATION_FAILED", seconds)
    def dump():
        device("shell", "uiautomator", "dump", "--compressed", "/data/local/tmp/phone-ui.xml")
        return device("exec-out", "cat", "/data/local/tmp/phone-ui.xml")
    def tap_text(text, initial=None):
        for _ in range(7):
            data = initial if initial is not None else dump()
            initial = None
            for n in ui(data):
                if label_matches(n.get("text"), text) and n.get("enabled") == "true":
                    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", n.get("bounds", ""))
                    if match:
                        x1, y1, x2, y2 = map(int, match.groups())
                        if 0 <= x1 < x2 <= W and 0 <= y1 < y2 <= H:
                            device("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2))
                            return
            device("shell", "input", "swipe", "540", "1600", "540", "550", "350")
        raise Refused("NATIVE_BUTTON_NOT_FOUND")
    def capture(name, check):
        evidence["uiCapture"] = name
        def observe_capture(data, active):
            nonlocal last_observation
            last_observation = 0  # Final samples require fresh ownership/window state.
            return observe_transition(data, active)
        raw, data = verified_capture_sample(dump, lambda: device("exec-out", "screencap", "-p"), check, observe_capture,
                                            min(20, max(1, deadline - time.monotonic())))
        rgb = png_rgb(raw)
        (artifacts / "raw" / name).write_bytes(raw)
        (artifacts / name).write_bytes(rgb)
        evidence["captures"].append({"name": name, "width": W, "height": H, "rgbBytes": len(rgb), "rgbSha256": hashlib.sha256(rgb).hexdigest(), "rawSha256": hashlib.sha256(raw).hexdigest()})
        return data
    def observe_transition(data, allow_hide):
        nonlocal last_observation, ime_hidden, last_ui_data, last_ui_snapshot, fullscreen_acknowledged, keyguard_dismissed
        last_ui_data = data
        if allow_hide and time.monotonic() - last_observation < 1:
            return
        last_observation = time.monotonic()
        owned = foreground(device("shell", "dumpsys", "activity", "activities").decode(errors="replace"))
        try:
            native_pid = bool(re.fullmatch(rb"\d+(?:\s+\d+)*", device("shell", "pidof", PACKAGE).strip()))
        except Refused:
            native_pid = False
        method = device("shell", "dumpsys", "input_method").decode(errors="replace")
        snapshot = ui_diagnostics(data, method, owned, native_pid)
        snapshot.update(window_diagnostics(device("shell", "dumpsys", "window", "policy").decode(errors="replace"),
                                           device("shell", "dumpsys", "window", "windows").decode(errors="replace")))
        known_help = {"Viewing full screen", "To exit, swipe down from the top of your screen", "Got it"}
        snapshot["knownSystemUiLabels"] = sorted({n.get(key) for n in ET.fromstring(data).iter("node")
                                                  if n.get("package") == "com.android.systemui" for key in ("text", "content-desc") if n.get(key) in known_help})
        last_ui_snapshot = snapshot
        evidence.setdefault("uiDiagnostics", []).append({"phase": ui_phase, **snapshot})
        evidence["uiDiagnostics"] = evidence["uiDiagnostics"][-8:]
        target = fullscreen_help_target(data, snapshot)
        if allow_hide and target is not None and not fullscreen_acknowledged:
            fullscreen_acknowledged = True
            evidence["fullscreenHelpAcknowledgementAttempted"] = True
            snapshot["observedSurfaceDismissed"] = True
            device("shell", "input", "tap", str(target[0]), str(target[1]))
            return snapshot  # Never use pre-tap IME/keyguard state for another action.
        if allow_hide and owned and native_pid and not keyguard_dismissed and can_dismiss_nonsecure_keyguard(snapshot):
            keyguard_dismissed = True
            evidence["nonsecureKeyguardDismissed"] = True
            snapshot["observedSurfaceDismissed"] = True
            device("shell", "wm", "dismiss-keyguard")
            return snapshot  # A fresh poll must observe the newly exposed surface.
        if allow_hide and not ime_hidden and can_hide_ime(snapshot, ui_phase):
            snapshot["imeDismissAttempted"] = True
            snapshot["observedSurfaceDismissed"] = True
            evidence.setdefault("imeDismissals", []).append(ui_phase)
            ime_hidden = True
            device("shell", "input", "keyevent", "KEYCODE_BACK")
        if not allow_hide:
            need(owned, "PLAYER_LEFT_FOREGROUND_DURING_UI")
            need(native_pid, "PLAYER_NATIVE_PID_UNVERIFIED")
        return snapshot
    def wait_ui(phase, check, seconds=20):
        nonlocal ui_phase, ime_hidden, last_observation
        ui_phase, ime_hidden, last_observation = phase, False, 0.0
        evidence["uiStage"] = phase
        evidence["uiStageHistory"].append(phase)
        return transition_wait(dump, check, observe_transition, seconds)
    try:
        need(all(p.exists() for p in (adb, tools / "aapt", tools / "apksigner", manager, avd)), "PREINSTALLED_TOOLS_MISSING")
        licenses = inspect_catalog(fetch(CATALOG, 8*1024**2), "emulator", pins["emulatorRevision"], pins["emulatorArchive"], {})
        licenses |= inspect_catalog(fetch(PHONE_CATALOG, 8*1024**2), IMAGE, pins["imageRevision"], pins["imageArchive"], pins["imageDependencies"])
        with_reviewed_licenses(sdk, state, licenses, lambda: command([manager, "--sdk_root=" + str(sdk), "--channel=0", "emulator", IMAGE], "SDK_INSTALL_FAILED", 480))
        for package, wanted, validation_stage in (("emulator", pins["emulatorRevision"], "VALIDATE_INSTALLED_EMULATOR"), (IMAGE, pins["imageRevision"], "VALIDATE_INSTALLED_PHONE")):
            stage = validation_stage
            stage_history.append(stage)
            inspect_installed(sdk, package, wanted)
        binary = sdk / "emulator/emulator"
        accel = command([binary, "-accel-check"], "KVM_CHECK_FAILED").decode(errors="replace")
        need(re.search(r"accel:\s*0", accel) and "KVM" in accel, "KVM_CHECK_FAILED")
        apk = state / "public.apk"
        data = fetch(APK_URL, APK_BYTES)
        need(len(data) == APK_BYTES and hashlib.sha256(data).hexdigest() == APK_SHA256, "PUBLIC_APK_HASH_MISMATCH")
        apk.write_bytes(data)
        signature = command([tools / "apksigner", "verify", "--print-certs", apk], "PUBLIC_APK_SIGNATURE_INVALID").decode(errors="replace")
        need("Signer #1 certificate SHA-256 digest: " + CERT in signature, "PUBLIC_APK_CERTIFICATE_UNEXPECTED")
        badging = command([tools / "aapt", "dump", "badging", apk], "PUBLIC_APK_MANIFEST_INVALID").decode(errors="replace")
        need("name='com.websignly.player'" in badging and "versionCode='5'" in badging and "versionName='1.0.4'" in badging, "PUBLIC_APK_IDENTITY_UNEXPECTED")
        profiles = command([avd, "list", "devices"], "PHONE_PROFILE_MISSING").decode(errors="replace")
        need('"pixel_2"' in profiles, "PHONE_PROFILE_MISSING")
        need(not avd_data.exists(), "AVD_DATA_ALREADY_EXISTS")
        command([avd, "create", "avd", "-n", AVD_NAME, "-k", IMAGE, "-d", "pixel_2", "-p", avd_data], "AVD_CREATE_FAILED", data=b"no\n")
        stage = "AVD_REGISTRY_VALIDATION"
        stage_history.append(stage)
        evidence["avdIdentity"] = validate_avd(state, avd_home, avd_data, sdk)
        listed = command([binary, "-list-avds"], "EMULATOR_AVD_DISCOVERY_FAILED").decode(errors="replace")
        need(AVD_NAME in [line.strip() for line in listed.splitlines()], "EMULATOR_AVD_DISCOVERY_FAILED")
        evidence["emulatorListsAvd"] = True
        for port in (int(PORT), 5556, 5557):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        command([adb, "-P", PORT, "start-server"], "OWN_ADB_START_FAILED")
        adb_started = True
        evidence["diskFreeBytesBeforeLaunch"] = disk_free(sdk, state)
        with (state / "emulator.log").open("wb") as log:
            process = subprocess.Popen([str(binary), "-avd", AVD_NAME, "-port", "5556", "-no-window", "-no-audio", "-no-boot-anim",
                                        "-no-snapshot", "-no-metrics", "-gpu", "swiftshader", "-accel", "on", "-cores", "2", "-memory", "3072",
                                        "-camera-back", "none", "-camera-front", "none"], stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        boot_end, booted = min(deadline, time.monotonic() + 240), False
        while time.monotonic() < boot_end and process.poll() is None:
            try:
                booted = device("shell", "getprop", "sys.boot_completed", seconds=10).strip() == b"1"
                if booted:
                    break
            except Refused:
                pass
            time.sleep(3)
        if not booted:
            evidence["emulatorExitCode"] = process.poll()
            evidence["bootDeadlineReached"] = time.monotonic() >= boot_end
            evidence["diskFreeBytesAfterFailure"] = disk_free(sdk, state)
            raise Refused("PHONE_BOOT_FAILED")
        need(device("shell", "getprop", "ro.build.version.sdk").strip() == b"36" and device("shell", "getprop", "ro.product.cpu.abi").strip() == b"x86_64", "PHONE_OS_IDENTITY_INVALID")
        features = device("shell", "pm", "list", "features").decode(errors="replace")
        need("android.hardware.touchscreen" in features and "android.hardware.type.television" not in features, "PHONE_FORM_FACTOR_INVALID")
        device("shell", "settings", "put", "global", "device_provisioned", "1")
        device("shell", "settings", "put", "secure", "user_setup_complete", "1")
        device("shell", "wm", "size", "1080x1920")
        device("shell", "wm", "density", "420")
        device("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        keyguard = window_diagnostics(device("shell", "dumpsys", "window", "policy").decode(errors="replace"), "")
        evidence["initialKeyguardState"] = keyguard
        if can_dismiss_nonsecure_keyguard(keyguard):
            device("shell", "wm", "dismiss-keyguard")
            keyguard_dismissed = True
        apk_install_started = True
        device("install", "--no-streaming", apk, seconds=60)
        device("shell", "am", "start", "-W", "-n", COMPONENT)
        wait_ui("PAIRING_WAIT", pairing, 75)
        pairing_data = capture("01-pairing.png", pairing)
        unpaired_flow = True
        tap_text("Settings", pairing_data)
        wait_ui("SETTINGS_TRANSITION", settings)
        settings_data = capture("02-settings.png", settings)
        tap_text("Privacy policy", settings_data)
        wait_ui("PRIVACY_TRANSITION", privacy, 45)
        privacy_data = capture("03-privacy.png", privacy)
        tap_text("Close", privacy_data)
        returned_settings = wait_ui("SETTINGS_TRANSITION", settings)
        tap_text("Resume playback", returned_settings)
        wait_ui("PAIRING_RETURN", pairing)
        evidence["status"] = "passed"
    except Exception as error:
        evidence["status"] = "failed"
        evidence.update(safe_error(error))
        if isinstance(error, Refused) and str(error) in {"UI_TRANSITION_TIMEOUT", "NATIVE_UI_MISSING", "PLAYER_LEFT_FOREGROUND_DURING_UI", "PLAYER_NATIVE_PID_UNVERIFIED", "CAPTURE_TRANSIENT_TIMEOUT", "CAPTURE_UI_INVALID", "CAPTURE_UNKNOWN_OVERLAY", "CAPTURE_OWNERSHIP_UNVERIFIED"}:
            try:
                snapshot = observe_transition(dump(), False)
                if snapshot and can_retain_ui(snapshot, unpaired_flow, evidence["organizationPaired"]):
                    diagnostic = png_rgb(device("exec-out", "screencap", "-p"))
                    need(foreground(device("shell", "dumpsys", "activity", "activities").decode(errors="replace")), "APP_NOT_FOREGROUND")
                    (artifacts / "ui-diagnostic-unpaired.png").write_bytes(diagnostic)
                    evidence["uiDiagnosticCaptureRetained"] = True
            except Exception as diagnostic_error:
                evidence["uiDiagnosticError"] = safe_error(diagnostic_error)
        raise
    finally:
        evidence["apkInstallAttempted"] = apk_install_started
        emulator_stopped = process is None
        if process is not None:
            evidence.setdefault("emulatorExitCode", process.poll())
            for signal_value, wait_seconds in ((signal.SIGTERM, 8), (signal.SIGKILL, 3)):
                try:
                    os.killpg(process.pid, signal_value)
                except ProcessLookupError:
                    emulator_stopped = True
                    break
                except OSError as error:
                    evidence.setdefault("cleanupErrors", []).append(safe_error(error))
                    break
                try:
                    process.wait(timeout=wait_seconds)
                except subprocess.TimeoutExpired:
                    pass
                stop_deadline = time.monotonic() + 1
                while time.monotonic() < stop_deadline:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        emulator_stopped = True
                        break
                    except OSError:
                        break
                    time.sleep(.1)
                if emulator_stopped:
                    break
            evidence["emulatorStopped"] = emulator_stopped
        if adb_started:
            try:
                subprocess.run([str(adb), "-P", PORT, "kill-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, env=env)
            except Exception:
                pass
        if evidence["status"] == "failed" and not apk_install_started and not evidence["organizationPaired"] and process is not None:
            try:
                with (state / "emulator.log").open("rb") as log:
                    size = log.seek(0, 2)
                    log.seek(0)
                    if size > BOOT_LIMIT:
                        part = (BOOT_LIMIT - len(BOOT_OMISSION)) // 2
                        head = log.read(part)
                        log.seek(-part, 2)
                        data = head + BOOT_OMISSION + log.read(part)
                    else:
                        data = log.read(BOOT_LIMIT)
                evidence["bootStartupCodes"] = boot_classifications(data)
                evidence["bootOutputRetained"] = can_retain_boot(evidence["status"], apk_install_started, evidence["organizationPaired"], True, emulator_stopped)
                if evidence["bootOutputRetained"]:
                    (artifacts / "boot-output-redacted.txt").write_text(boot_output(data))
            except Exception as error:
                evidence["bootOutputDiagnosticError"] = safe_error(error)
        evidence["stage"], evidence["elapsedSeconds"] = stage, round(time.monotonic() - started)
        evidence["stageHistory"] = stage_history[-32:]
        (artifacts / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({key: evidence[key] for key in ("status", "stage", "uiStage", "uiCapture", "error", "exceptionType", "errno", "operationPhase", "commandExitCode", "sdkDiagnostic", "sdkCommandExitCode", "sdkWarningCodes", "sdkPackage", "expectedMetadata", "sourcePropertiesExists", "emulatorExitCode", "bootDeadlineReached", "diskFreeBytesBeforeLaunch", "diskFreeBytesAfterFailure", "bootStartupCodes", "emulatorStopped", "bootOutputRetained", "cleanupErrors") if key in evidence} | {"captures": len(evidence["captures"])}))


def self_test():
    # In-memory fixtures only. Never export synthetic PNGs as captures.
    def rejects(call):
        try:
            call()
        except Refused:
            return True
        return False
    def xml(values, package=PACKAGE):
        root = ET.Element("hierarchy")
        for value in values:
            ET.SubElement(root, "node", {"package": package, "text": value})
        return ET.tostring(root)
    checks = [rejects(lambda: validate_pins({})), pairing(xml(["123456", "Your next great screen"])),
              not pairing(xml(["··· ···", "Your next great screen"])), rejects(lambda: ui(xml(["123456"], "foreign"))),
              privacy(xml(["WebSignly privacy policy", "WebOrbit LLC", "Close"])),
              privacy(xml(["WebSignly privacy policy", "WebOrbit LLC", "CLOSE"])),
              not privacy(xml(["WebSignly privacy policy", "CLOSE"])),
              not privacy(xml(["WebSignly privacy policy", "WebOrbit LLC", "Close account"])),
              label_matches("CLOSE", "Close"), not label_matches("CLOSE account", "Close"),
              not label_matches("SETTINGS", "Settings"),
              not privacy(xml(["WebSignly privacy policy", "Loading privacy policy…", "Close"])),
              foreground("topResumedActivity=ActivityRecord{ test com.websignly.player/.MainActivity t1}"),
              not foreground("topResumedActivity=ActivityRecord{ test other/.MainActivity t1}"),
              rejects(lambda: png_rgb(b"not-png"))]
    def fixture(rows, channels, method):
        previous, encoded = bytes(len(rows[0])), bytearray()
        for row in rows:
            encoded.append(method)
            for x, sample in enumerate(row):
                left = row[x - channels] if x >= channels else 0
                up, corner = previous[x], previous[x - channels] if x >= channels else 0
                estimate = left + up - corner
                paeth = min(enumerate((left, up, corner)), key=lambda pair: (abs(estimate - pair[1]), pair[0]))[1]
                encoded.append((sample - (0, left, up, (left + up) // 2, paeth)[method]) & 255)
            previous = row
        def chunk(kind, body):
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 2, 8, 2 if channels == 3 else 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(encoded, 6)) + chunk(b"IEND", b"")
    rgb_rows = [bytes(range(24)), bytes(range(41, 65))]
    rgba_rows = [b"".join(row[x:x+3] + b"\xff" for x in range(0, len(row), 3)) for row in rgb_rows]
    expected = fixture(rgb_rows, 3, 0)
    for channels, rows in ((3, rgb_rows), (4, rgba_rows)):
        for method in range(5):
            checks.append(png_rgb(fixture(rows, channels, method), 8, 2) == expected)
    translucent = [rgba_rows[0][:-1] + b"\0", rgba_rows[1]]
    checks.extend([rejects(lambda: png_rgb(fixture(translucent, 4, 0), 8, 2)),
                   rejects(lambda: png_rgb(expected)), rejects(lambda: png_rgb(expected[:-1] + b"\0", 8, 2))])
    pins = json.loads(Path(__file__).with_name("pins.json").read_text())
    validate_pins(pins)
    fixture_license = "Synthetic unit-test terms; never approval of an SDK license."
    fixture_license_hash = hashlib.sha256(fixture_license.encode()).hexdigest()
    def catalog(package, wanted, archive, dependencies):
        root = ET.Element("sdk-repository")
        ET.SubElement(root, "license", {"id": "android-sdk-license"}).text = fixture_license
        node = ET.SubElement(root, "remotePackage", {"path": package})
        def rev(parent, name, values):
            target = ET.SubElement(parent, name)
            for key, value in zip(("major", "minor", "micro"), values):
                ET.SubElement(target, key).text = str(value)
        rev(node, "revision", wanted)
        ET.SubElement(node, "channelRef", {"ref": "channel-0"})
        ET.SubElement(node, "uses-license", {"ref": "android-sdk-license"})
        if dependencies:
            deps = ET.SubElement(node, "dependencies")
            for path, values in dependencies.items():
                rev(ET.SubElement(deps, "dependency", {"path": path}), "min-revision", values)
        entry = ET.SubElement(ET.SubElement(node, "archives"), "archive")
        ET.SubElement(entry, "host-os").text = "linux"
        complete = ET.SubElement(entry, "complete")
        ET.SubElement(complete, "url").text = archive["url"]
        ET.SubElement(complete, "size").text = str(archive["size"])
        ET.SubElement(complete, "checksum", {"type": "sha1"}).text = archive["sha1"]
        return ET.tostring(root)
    image_catalog = catalog(IMAGE, pins["imageRevision"], pins["imageArchive"], pins["imageDependencies"])
    emulator_catalog = catalog("emulator", pins["emulatorRevision"], pins["emulatorArchive"], {})
    def inspect_fixture(data, package, wanted, archive, deps):
        return inspect_catalog(data, package, wanted, archive, deps, expected_license=fixture_license_hash)
    checks.append(inspect_fixture(image_catalog, IMAGE, pins["imageRevision"], pins["imageArchive"], pins["imageDependencies"]) is not None)
    checks.append(inspect_fixture(emulator_catalog, "emulator", pins["emulatorRevision"], pins["emulatorArchive"], {}) is not None)
    checks.append(rejects(lambda: inspect_fixture(image_catalog, IMAGE, [999, 0, 0], pins["imageArchive"], pins["imageDependencies"])))
    checks.append(rejects(lambda: inspect_fixture(image_catalog, IMAGE, pins["imageRevision"], pins["imageArchive"], {})))
    checks.append(rejects(lambda: inspect_fixture(image_catalog, IMAGE, pins["imageRevision"], {**pins["imageArchive"], "sha1": "0" * 40}, pins["imageDependencies"])))
    checks.append(rejects(lambda: inspect_catalog(image_catalog, IMAGE, pins["imageRevision"], pins["imageArchive"], pins["imageDependencies"])))
    # Synthetic directories and injected failures only; never invoke SDKmanager.
    import tempfile
    from unittest.mock import patch
    with tempfile.TemporaryDirectory(prefix="public-phone-license-test-") as temporary:
        base = Path(temporary)
        sdk, state = base / "sdk", base / "state"
        (sdk / "licenses").mkdir(parents=True)
        state.mkdir()
        (sdk / "licenses" / "original-license").write_text("original synthetic content")
        failure = Refused("SDK_INSTALL_FAILED")
        def install_failure():
            need(set(p.name for p in (sdk / "licenses").iterdir()) == {"android-sdk-license"}, "FIXTURE_EXTRA_ACCEPTANCE")
            (sdk / "licenses" / "extra-sdk-file").write_text("synthetic SDK output")
            raise failure
        try:
            with_reviewed_licenses(sdk, state, {"a" * 40}, install_failure)
            checks.append(False)
        except Refused as observed:
            checks.append(observed is failure and str(observed) == "SDK_INSTALL_FAILED")
        checks.append((sdk / "licenses" / "original-license").read_text() == "original synthetic content")
        quarantines = list(sdk.glob(".phone-capture-license-state-*"))
        checks.append(len(quarantines) == 1 and (quarantines[0] / "extra-sdk-file").read_text() == "synthetic SDK output")
        checks.append(not (sdk / "licenses" / "android-sdk-license").exists())
    with tempfile.TemporaryDirectory(prefix="public-phone-license-test-") as temporary:
        base = Path(temporary)
        sdk, state = base / "sdk", base / "state"
        sdk.mkdir()
        state.mkdir()
        original_rename = Path.rename
        failure = Refused("SDK_INSTALL_FAILED")
        def fail_cleanup(path, target):
            if Path(target).name.startswith(".phone-capture-license-state-"):
                raise PermissionError(13, "synthetic-hidden-message")
            return original_rename(path, target)
        with patch.object(Path, "rename", fail_cleanup):
            try:
                with_reviewed_licenses(sdk, state, {"a" * 40}, lambda: (_ for _ in ()).throw(failure))
                checks.append(False)
            except Refused as observed:
                checks.append(observed is failure and safe_error(observed)["cleanupErrors"][0]["errno"] == 13)
    with tempfile.TemporaryDirectory(prefix="public-phone-license-test-") as temporary:
        base = Path(temporary)
        sdk, state = base / "sdk", base / "state"
        sdk.mkdir()
        state.mkdir()
        with patch.object(Path, "rename", fail_cleanup):
            try:
                with_reviewed_licenses(sdk, state, {"a" * 40}, lambda: None)
                checks.append(False)
            except Refused as observed:
                checks.append(str(observed) == "SDK_LICENSE_RESTORE_FAILED")
    checks.append(safe_error(FileNotFoundError(2, "synthetic-hidden-value", "/synthetic/private-name")) == {"error": "CAPTURE_OPERATION_FAILED", "exceptionType": "FileNotFoundError", "errno": 2})
    checks.append("synthetic-hidden-message" not in json.dumps(safe_error(failure)))
    checks.append(sdk_diagnostic(b"Warning: License for package emulator not accepted. synthetic-hidden-value") == "SDK_LICENSE_NOT_ACCEPTED")
    checks.append(sdk_diagnostic(b"Error: JAVA_HOME is set to an invalid directory") == "SDK_JAVA_HOME_INVALID")
    checks.append(sdk_diagnostic(b"unknown synthetic-hidden-value") == "SDK_INSTALL_OTHER")
    for original, expected_license_text in (("A\nB", "A B"), ("A\n\nB", "A\n\nB"), ("A  B", "A B"),
                                            ("A\t B", "A\tB"), ("A \t B", "A B"), ("\u00a0A\u00a0", "\u00a0A\u00a0"),
                                            (" \tAlpha \n    beta  \n\n   gamma\t \n ", "Alpha beta \n\ngamma")):
        checks.append(normalized_license(original) == expected_license_text)
    try:
        check_sdk_result(0, b"Warning: License for package emulator not accepted. synthetic-hidden-value")
        checks.append(False)
    except Refused as observed:
        checks.append(safe_error(observed)["commandExitCode"] == 0 and safe_error(observed)["sdkDiagnostic"] == "SDK_LICENSE_NOT_ACCEPTED")
    checks.append(check_sdk_result(0, b"All SDK package licenses accepted.") == [])
    checks.append(sdk_summary(b"Warning: Observed package id 'synthetic-hidden-value' in inconsistent location /synthetic/private-path") == ["SDK_PACKAGE_LAYOUT_WARNING"])
    with tempfile.TemporaryDirectory(prefix="public-phone-metadata-test-") as temporary:
        sdk = Path(temporary)
        (sdk / "emulator").mkdir()
        (sdk / "emulator/source.properties").write_text("Pkg.Revision=37.2.12\n")
        try:
            inspect_installed(sdk, "emulator", [37, 2, 12])
            checks.append(False)
        except Refused as observed:
            detail = safe_error(observed)
            checks.append(detail["error"] == "INSTALLED_SDK_METADATA_MISSING" and detail["sdkPackage"] == "emulator"
                          and detail["expectedMetadata"] == "emulator/package.xml" and detail["sourcePropertiesExists"] is True)
        (sdk / "emulator/package.xml").write_text('<repository><localPackage path="emulator"><revision><major>37</major><minor>2</minor><micro>12</micro></revision></localPackage></repository>')
        checks.append(inspect_installed(sdk, "emulator", [37, 2, 12]) is None)
        checks.append(rejects(lambda: inspect_installed(sdk, "emulator", [999, 0, 0])))
        original_is_file = Path.is_file
        def fail_optional_diagnostic(path):
            if Path(path).name == "source.properties":
                raise PermissionError(13, "synthetic-hidden-message")
            return False if Path(path).name == "package.xml" else original_is_file(path)
        with patch.object(Path, "is_file", fail_optional_diagnostic):
            try:
                inspect_installed(sdk, "emulator", [37, 2, 12])
                checks.append(False)
            except Refused as observed:
                checks.append(str(observed) == "INSTALLED_SDK_METADATA_MISSING")
    sensitive = b'PANIC: Not enough disk space in /home/runner/private-path\n token=synthetic-sensitive-value key=another-sensitive-value Authorization: Bearer fake-bearer-value\n aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee 01:23:45:67:89:ab https://example.invalid/?token=hidden C:\\Users\\Synthetic\\private\n aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc\n'
    sanitized = boot_output(sensitive)
    checks.append("PANIC: Not enough disk space" in sanitized)
    checks.append(all(value not in sanitized for value in ("synthetic-sensitive-value", "another-sensitive-value", "fake-bearer-value", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "01:23:45:67:89:ab", "private-path", "example.invalid", "Synthetic", "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc")))
    checks.append(len(boot_output(b"x" * 200000).encode()) <= BOOT_LIMIT and "middle omitted" in boot_output(b"x" * 200000))
    checks.append(boot_classifications(b"PANIC: Not enough disk space to run AVD") == ["BOOT_DISK_SPACE"])
    checks.append(boot_classifications(b"Unknown option: -synthetic") == ["BOOT_CLI_OPTION"])
    checks.append(boot_classifications(b"nothing recognized") == ["BOOT_REASON_UNCLASSIFIED"])
    checks.append(can_retain_boot("failed", False, False, True, True))
    checks.append(not can_retain_boot("passed", False, False, True, True))
    checks.append(not can_retain_boot("failed", True, False, True, True))
    checks.append(not can_retain_boot("failed", False, True, True, True))
    checks.append(not can_retain_boot("failed", False, False, False, True))
    checks.append(not can_retain_boot("failed", False, False, True, False))
    with tempfile.TemporaryDirectory(prefix="public-phone-disk-test-") as temporary:
        free = disk_free(Path(temporary), Path(temporary))
        checks.append(type(free["sdk"]) is int and free["sdk"] > 0 and free["state"] > 0)
    with tempfile.TemporaryDirectory(prefix="public-phone-avd-test-") as temporary:
        state = Path(temporary)
        avd_home, user_home = create_avd_roots(state)
        checks.append(avd_home.is_dir() and user_home.is_dir() and avd_home.parent == state and user_home.parent == state)
        sdk, avd_data = state / "sdk", avd_home / (AVD_NAME + ".avd")
        avd_data.mkdir()
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
        index = avd_home / (AVD_NAME + ".ini")
        index.write_text("path=" + str(avd_data.resolve()) + "\ntarget=android-36\n")
        config = avd_data / "config.ini"
        valid_config = "abi.type=x86_64\nhw.cpu.arch=x86_64\ntag.id=google_apis\nimage.sysdir.1=system-images/android-36/google_apis/x86_64/\nAvdId=" + AVD_NAME + "\n"
        config.write_text(valid_config)
        checks.append(validate_avd(state, avd_home, avd_data, sdk)["configImageMatches"] is True)
        index.write_text("path=" + str((state.parent / "outside-data").resolve()) + "\n")
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
        index.write_text("path=" + str(avd_data.resolve()) + "\n")
        config.write_text(valid_config.replace("android-36", "android-35"))
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
        config.write_text(valid_config.replace("abi.type=x86_64", "abi.type=arm64-v8a"))
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
        config.write_text(valid_config + "image.sysdir.2=unapproved-image\n")
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
        config.write_text(valid_config + "abi.type=x86_64\n")
        checks.append(rejects(lambda: validate_avd(state, avd_home, avd_data, sdk)))
    tick, observations = [0.0], []
    def now():
        return tick[0]
    def pause(seconds):
        tick[0] += seconds
    transient = iter([xml(["keyboard"], "com.android.inputmethod.latin"), xml(["ready"])])
    checks.append(transition_wait(lambda: next(transient), lambda data: "ready" in [n.get("text") for n in ui(data)],
                                  lambda data, active: observations.append(active), 2, now, pause) == xml(["ready"]))
    checks.append(observations == [True, True])
    refreshed = []
    def read_after_surface():
        refreshed.append(True)
        return xml(["ready"])
    def observe_surface(data, active):
        return {"observedSurfaceDismissed": len(refreshed) == 1}
    transition_wait(read_after_surface, lambda data: True, observe_surface, 2, now, pause)
    checks.append(len(refreshed) == 2)
    failures = [0]
    def invalid_check(data):
        failures[0] += 1
        raise Refused("UI_DUMP_TOO_LARGE")
    checks.append(rejects(lambda: transition_wait(lambda: b"", invalid_check, lambda *_: None, 2, now, pause)) and failures[0] == 1)
    tick[0] = 0.0
    persistent_observations = []
    try:
        transition_wait(lambda: xml(["keyboard"], "com.android.inputmethod.latin"), pairing,
                        lambda data, active: persistent_observations.append(active), .9, now, pause)
        checks.append(False)
    except Refused as observed:
        checks.append(str(observed) == "UI_TRANSITION_TIMEOUT" and persistent_observations[-1] is False and len(persistent_observations) <= 5)
    snapshot = ui_diagnostics(xml(["keyboard"], "com.android.inputmethod.latin"),
                              "mInputShown=true mImeWindowVis=0x3 mCurId=com.android.inputmethod.latin/.LatinIME", True, True)
    checks.append(can_hide_ime(snapshot, "SETTINGS_TRANSITION"))
    checks.append(not can_hide_ime({**snapshot, "ownedForeground": False}, "SETTINGS_TRANSITION"))
    checks.append(not can_hide_ime({**snapshot, "nativePidPresent": False}, "SETTINGS_TRANSITION"))
    checks.append(not can_hide_ime({**snapshot, "imeVisible": False}, "SETTINGS_TRANSITION"))
    checks.append(not can_hide_ime({**snapshot, "imeShown": False}, "SETTINGS_TRANSITION"))
    checks.append(not can_hide_ime(snapshot, "PAIRING_RETURN"))
    checks.append(can_retain_ui(snapshot, True, False))
    checks.append(not can_retain_ui(snapshot, False, False))
    checks.append(not can_retain_ui(snapshot, True, True))
    checks.append(not can_retain_ui({**snapshot, "nativePidPresent": False}, True, False))
    checks.append(not can_retain_ui({**snapshot, "packages": ["other.credentials.app"]}, True, False))
    summary = ui_diagnostics(xml(["PLAYER SETTINGS", "synthetic-private-text"]), "mInputShown=false", True, True)
    checks.append(summary["ownLabels"] == ["PLAYER SETTINGS"] and "synthetic-private-text" not in json.dumps(summary))
    checks.append(settings(xml(["PLAYER SETTINGS", "Ready to pair\nActive revision: none", "Privacy policy"])))
    checks.append(not settings(xml(["PLAYER SETTINGS", "Ready to pair\nActive revision: none", "Privacy policy", "Unpair and remove local content"])))
    def help_xml(body="To exit, swipe down from the top of your screen", button_id="com.android.systemui:id/ok", package="com.android.systemui", title=True):
        root = ET.Element("hierarchy")
        if title:
            ET.SubElement(root, "node", {"package": package, "text": "Viewing full screen"})
        ET.SubElement(root, "node", {"package": package, "text": body, "resource-id": "com.android.systemui:id/immersive_cling_description"})
        ET.SubElement(root, "node", {"package": package, "text": "Got it", "resource-id": button_id, "class": "android.widget.Button", "clickable": "true", "enabled": "true", "bounds": "[600,1400][1000,1600]"})
        return ET.tostring(root)
    help_state = {"ownedForeground": True, "nativePidPresent": True, "keyguardShowing": False, "keyguardSecure": False, "immersiveWindowPresent": True}
    checks.append(fullscreen_help_target(help_xml(), help_state) == (800, 1500))
    checks.append(fullscreen_help_target(help_xml(title=False), help_state) == (800, 1500))
    checks.append(fullscreen_help_target(help_xml(title=False), {**help_state, "immersiveWindowPresent": False}) is None)
    checks.append(fullscreen_help_target(help_xml(body="Review and accept these terms"), help_state) is None)
    checks.append(fullscreen_help_target(help_xml(button_id="com.android.systemui:id/unrelated"), help_state) is None)
    checks.append(fullscreen_help_target(help_xml(package=PACKAGE), help_state) is None)
    checks.append(fullscreen_help_target(help_xml(), {**help_state, "ownedForeground": False}) is None)
    checks.append(fullscreen_help_target(help_xml(), {**help_state, "nativePidPresent": False}) is None)
    checks.append(fullscreen_help_target(help_xml(), {**help_state, "keyguardShowing": True}) is None)
    checks.append(fullscreen_help_target(help_xml(), {**help_state, "keyguardSecure": True}) is None)
    keyguard = window_diagnostics("KeyguardServiceDelegate\n  showing=true\n  inputRestricted=true\n  occluded=false\n  secure=false\n", "Window ImmersiveModeConfirmation")
    checks.append(can_dismiss_nonsecure_keyguard(keyguard) and keyguard["immersiveWindowPresent"] is True)
    checks.append(not can_dismiss_nonsecure_keyguard({**keyguard, "keyguardSecure": True}))
    checks.append(not can_dismiss_nonsecure_keyguard(window_diagnostics("unknown", "")))
    def scene_check(data):
        if data == b"help":
            raise Refused("NATIVE_UI_MISSING")
        return data == b"ready"
    def scene_observer(data, active):
        return {"ownedForeground": True, "nativePidPresent": True, "packages": [PACKAGE] if data == b"ready" else ["com.android.systemui"],
                "immersiveWindowPresent": data == b"help", "observedSurfaceDismissed": data == b"help"}
    tick[0] = 0.0
    sequence = iter([b"ready", b"help", b"ready", b"ready"])
    frames, frame_count = iter([b"overlay-frame", b"clean-frame"]), [0]
    def grab_frame():
        frame_count[0] += 1
        return next(frames)
    accepted, scene = verified_capture_sample(lambda: next(sequence), grab_frame, scene_check, scene_observer, 3, now, pause)
    checks.append(accepted == b"clean-frame" and frame_count[0] == 2 and scene == b"ready")
    sequence = iter([b"help", b"ready", b"ready"])
    grabs = []
    accepted, scene = verified_capture_sample(lambda: next(sequence), lambda: grabs.append(True) or b"clean", scene_check, scene_observer, 3, now, pause)
    checks.append(accepted == b"clean" and len(grabs) == 1)
    tick[0] = 0.0
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"help", lambda: b"never", scene_check, scene_observer, .9, now, pause)))
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"invalid", lambda: b"never", scene_check,
                                                        lambda *_: {"ownedForeground": True, "nativePidPresent": True, "packages": [PACKAGE]}, 1, now, pause)))
    before_failures = failures[0]
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"ready", lambda: b"never", invalid_check, scene_observer, 1, now, pause)) and failures[0] == before_failures + 1)
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"ready", lambda: b"never", scene_check,
                                                        lambda *_: {"ownedForeground": False, "nativePidPresent": True, "packages": [PACKAGE]}, 1, now, pause)))
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"ready", lambda: b"never", scene_check,
                                                        lambda *_: {"ownedForeground": True, "nativePidPresent": False, "packages": [PACKAGE]}, 1, now, pause)))
    checks.append(rejects(lambda: verified_capture_sample(lambda: b"ready", lambda: b"never", scene_check,
                                                        lambda *_: {"ownedForeground": True, "nativePidPresent": True, "packages": [PACKAGE, "com.android.systemui"]}, 1, now, pause)))
    sequence = iter([b"ready", b"invalid"])
    checks.append(rejects(lambda: verified_capture_sample(lambda: next(sequence), lambda: b"invalid-frame", scene_check,
                                                        lambda *_: {"ownedForeground": True, "nativePidPresent": True, "packages": [PACKAGE]}, 1, now, pause)))
    need(all(checks), "SYNTHETIC_CHECK_FAILED")
    print(json.dumps({"passed": True, "checks": len(checks), "networkRequests": 0, "sdkInstalls": 0, "emulatorStarts": 0}))


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test()
        elif sys.argv[1:] == ["--plan"] or not sys.argv[1:]:
            print(json.dumps({"mode": "offline-plan", "image": IMAGE, "apkSha256": APK_SHA256, "captures": ["native pairing", "native standalone settings", "native privacy"], "requiresReviewedPins": True, "networkRequests": 0}))
        elif sys.argv[1:] == ["--run"]:
            run(json.loads(Path(__file__).with_name("pins.json").read_text()))
        else:
            raise Refused("USE_PLAN_SELF_TEST_OR_RUN")
    except Exception as error:
        print(json.dumps({"status": "refused", **safe_error(error)}))
        sys.exit(1)

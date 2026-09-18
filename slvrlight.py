# -*- coding: utf-8 -*-
#
# WCF Binary SOAP (msbin1) editor tab for Burp Suite  -  Jython 2.7 extension
# ---------------------------------------------------------------------------
# Adds a "WCF (msbin1)" tab to Burp's request/response editors (Repeater,
# Proxy intercept, etc). It:
#   * auto-detects Content-Type: application/soap+msbin1 (and the compressed
#     application/x-zip / application/x-gzip variants),
#   * decompresses the body if needed,
#   * decodes the .NET Binary XML (NBFS) body to readable XML using NBFS.exe,
#   * lets you edit that XML, and
#   * on send, re-encodes it back to binary and re-compresses it so the WCF
#     endpoint accepts your modified message.
#
# Credit: NBFS.exe is Brian Holyfield / Gotham Digital Science's tool from the
# original "WCF-Binary-SOAP-Plug-In". This extension only reuses that binary;
# the Burp integration is a modern rewrite (the original used a Burp API that
# no longer exists in current Burp versions).
#
# ---- SETUP -----------------------------------------------------------------
# 1. Install Jython 2.7 standalone jar and point Burp at it:
#      Extensions -> Extensions settings -> Python environment.
# 2. Put NBFS.exe somewhere and set NBFS_PATH below.
# 3. Load: Extensions -> Installed -> Add -> Type: Python -> select this file.
# 4. Check the extension's Output tab: it prints a self-test (should say PASS).
# 5. Use it: right-click a msbin1 request -> Send to Repeater. You'll see a
#      "WCF (msbin1)" tab next to Raw/Hex. Edit the XML there and hit Send.
#
# On Linux/macOS Burp cannot run a .exe directly. Install mono and set:
#      NBFS_INVOCATION = ["mono", NBFS_PATH]
#
# NOTE (limitation inherited from NBFS.exe): the payload is passed to NBFS on
# the command line as base64. Windows caps a command line at ~32k chars, so a
# body larger than ~24 KB may get truncated. Your sample requests (~1.5 KB) are
# well within range.
# ---------------------------------------------------------------------------

from __future__ import print_function

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.util import Base64, Arrays, ArrayList
from java.lang import ProcessBuilder, StringBuilder
from java.lang import String as JString
from java.io import BufferedReader, InputStreamReader, ByteArrayInputStream, ByteArrayOutputStream
from java.util.zip import GZIPInputStream, GZIPOutputStream, Inflater, Deflater
import jarray
import os

# ============================ CONFIG =======================================
NBFS_PATH = r"C:\Tools\NBFS.exe"          # <-- EDIT THIS to your NBFS.exe path
NBFS_INVOCATION = [NBFS_PATH]             # Linux/mac: ["mono", NBFS_PATH]

# NBFS operation verbs. The released NBFS.exe is case-insensitive; if you ever
# see a "Usage:" message in the output, switch these to "DECODE" / "ENCODE".
OP_DECODE = "decode"
OP_ENCODE = "encode"

# Content-Types that turn the tab on. Add more if your app uses others.
ENABLE_ON_TYPES = [
    "application/soap+msbin1",
    "application/msbin1",
    "application/x-zip",
    "application/x-gzip",
]

TAB_CAPTION = "WCF (msbin1)"
# ===========================================================================


# --------------------------- small helpers ---------------------------------
def str_to_jbytes(s):
    """Python/Java string -> UTF-8 java byte[]."""
    return JString(s).getBytes("UTF-8")


def jbytes_to_str(jb):
    """UTF-8 java byte[] -> string."""
    return JString(jb, "UTF-8")


def _read_all(ins):
    bos = ByteArrayOutputStream()
    buf = jarray.zeros(8192, "b")
    n = ins.read(buf)
    while n != -1:
        bos.write(buf, 0, n)
        n = ins.read(buf)
    return bos.toByteArray()


# --------------------------- (de)compression -------------------------------
def detect_compression(body):
    if body is None or len(body) < 2:
        return "none"
    b0 = body[0] & 0xFF
    b1 = body[1] & 0xFF
    if b0 == 0x1F and b1 == 0x8B:
        return "gzip"
    if b0 == 0x78 and b1 in (0x01, 0x9C, 0xDA):
        return "zlib"
    if b0 == 0x50 and b1 == 0x4B:            # "PK" -> real ZIP archive
        return "pkzip"
    return "none"


def _gunzip(data):
    gis = GZIPInputStream(ByteArrayInputStream(data))
    out = _read_all(gis)
    gis.close()
    return out


def _gzip(data):
    bos = ByteArrayOutputStream()
    gos = GZIPOutputStream(bos)
    gos.write(data, 0, len(data))
    gos.finish()
    gos.close()
    return bos.toByteArray()


def _inflate(data, nowrap):
    inf = Inflater(nowrap)
    inf.setInput(data)
    bos = ByteArrayOutputStream()
    buf = jarray.zeros(8192, "b")
    while not inf.finished():
        n = inf.inflate(buf)
        if n == 0 and (inf.needsInput() or inf.needsDictionary()):
            break
        bos.write(buf, 0, n)
    inf.end()
    return bos.toByteArray()


def _deflate(data, nowrap):
    d = Deflater(Deflater.DEFAULT_COMPRESSION, nowrap)
    d.setInput(data)
    d.finish()
    bos = ByteArrayOutputStream()
    buf = jarray.zeros(8192, "b")
    while not d.finished():
        n = d.deflate(buf)
        bos.write(buf, 0, n)
    d.end()
    return bos.toByteArray()


def decompress(body, comp):
    if comp == "gzip":
        return _gunzip(body)
    if comp == "zlib":
        return _inflate(body, False)
    return body            # "none"


def recompress(data, comp):
    if comp == "gzip":
        return _gzip(data)
    if comp == "zlib":
        return _deflate(data, False)
    return data            # "none"


# ------------------------------- NBFS --------------------------------------
def run_nbfs(op, data_bytes):
    """
    Call NBFS.exe. Input and output are base64 (that's NBFS's contract).
    Returns ("ok", java_byte[])  on base64 output,
            ("err", raw_string)  if NBFS printed something non-base64.
    """
    b64_in = Base64.getEncoder().encodeToString(data_bytes)
    cmd = ArrayList()
    for c in NBFS_INVOCATION:
        cmd.add(c)
    cmd.add(op)
    cmd.add(b64_in)

    pb = ProcessBuilder(cmd)
    pb.redirectErrorStream(True)
    proc = pb.start()
    reader = BufferedReader(InputStreamReader(proc.getInputStream()))
    sb = StringBuilder()
    line = reader.readLine()
    while line is not None:
        sb.append(line)
        line = reader.readLine()
    reader.close()
    proc.waitFor()

    out = sb.toString().strip()
    if not out:
        return ("err", "NBFS returned no output")
    try:
        return ("ok", Base64.getDecoder().decode(out))
    except Exception:
        return ("err", out)


def decode_to_xml_bytes(msbin_bytes):
    """Returns (ok_bool, byte[] to display)."""
    status, out = run_nbfs(OP_DECODE, msbin_bytes)
    if status == "err":
        return (False, str_to_jbytes("[NBFS did not return base64]\n\n" + out))
    # Find first meaningful byte (skip whitespace + UTF-8 BOM).
    i, n = 0, len(out)
    skip = (0x20, 0x09, 0x0A, 0x0D, 0xEF, 0xBB, 0xBF)
    while i < n and (out[i] & 0xFF) in skip:
        i += 1
    if i < n and (out[i] & 0xFF) == 0x3C:        # '<'  -> looks like XML
        return (True, out)
    # NBFS reports its own errors as base64-wrapped text.
    return (False, str_to_jbytes("[NBFS decode error]\n\n" + str(jbytes_to_str(out))))


def looks_like_nbfs_error(encoded):
    """After encode, msbin1 is mostly binary; if the output is ASCII text with
    an error marker, NBFS choked on the XML. Guards against sending garbage."""
    try:
        low = str(jbytes_to_str(encoded)).lower()
    except Exception:
        return False
    for m in ("exception", "usage:", "stack trace", "is not valid", "unexpected"):
        if m in low:
            return True
    return False


def strip_content_length(headers):
    out = ArrayList()
    for h in headers:
        if not h.lower().startswith("content-length:"):
            out.add(h)
    return out


# ---------------------------- the editor tab -------------------------------
class WCFTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._helpers = extender._helpers
        self._callbacks = extender._callbacks
        self._editable = editable
        self._txt = extender._callbacks.createTextEditor()
        self._txt.setEditable(editable)
        self._current = None
        self._isRequest = True
        self._comp = "none"
        self._decoded_ok = False

    def getTabCaption(self):
        return TAB_CAPTION

    def getUiComponent(self):
        return self._txt.getComponent()

    def _info(self, content, isRequest):
        if isRequest:
            return self._helpers.analyzeRequest(content)
        return self._helpers.analyzeResponse(content)

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            info = self._info(content, isRequest)
            ct = ""
            for h in info.getHeaders():
                if h.lower().startswith("content-type:"):
                    ct = h.lower()
                    break
            for t in ENABLE_ON_TYPES:
                if t in ct:
                    return True
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            if len(body) >= 2 and (body[0] & 0xFF) == 0x1F and (body[1] & 0xFF) == 0x8B:
                return True
            return False
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self._current = content
        self._isRequest = isRequest
        if content is None:
            self._txt.setText(None)
            self._txt.setEditable(False)
            self._decoded_ok = False
            return
        try:
            info = self._info(content, isRequest)
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            self._comp = detect_compression(body)

            if self._comp == "pkzip":
                self._txt.setText(str_to_jbytes(
                    "[This body is a PKZIP/ZIP archive, not WCF binary XML - nothing to decode here.]"))
                self._txt.setEditable(False)
                self._decoded_ok = False
                return

            msbin = decompress(body, self._comp)
            ok, xmlbytes = decode_to_xml_bytes(msbin)
            self._decoded_ok = ok
            self._txt.setText(xmlbytes)
            self._txt.setEditable(self._editable and ok)
        except Exception as e:
            self._decoded_ok = False
            self._txt.setText(str_to_jbytes("[WCF tab error] " + str(e)))
            self._txt.setEditable(False)

    def getMessage(self):
        if self._current is None:
            return self._current
        if (not self._decoded_ok) or (not self._txt.isTextModified()):
            return self._current
        try:
            xmlbytes = self._txt.getText()             # java byte[]
            status, encoded = run_nbfs(OP_ENCODE, xmlbytes)
            if status == "err" or looks_like_nbfs_error(encoded):
                # Could not re-encode (e.g. malformed XML): leave message untouched.
                return self._current
            newbody = recompress(encoded, self._comp)
            info = self._info(self._current, self._isRequest)
            headers = strip_content_length(info.getHeaders())
            return self._helpers.buildHttpMessage(headers, newbody)
        except Exception:
            return self._current

    def isModified(self):
        return self._txt.isTextModified()

    def getSelectedData(self):
        return self._txt.getSelectedText()


# ------------------------------ entry point --------------------------------
class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WCF Binary SOAP (msbin1) Editor")
        callbacks.registerMessageEditorTabFactory(self)

        print("=== WCF Binary SOAP (msbin1) Editor loaded ===")
        print("NBFS invocation :", NBFS_INVOCATION)
        try:
            exists = os.path.isfile(NBFS_PATH)
        except Exception:
            exists = False
        print("NBFS_PATH found :", exists, "(" + NBFS_PATH + ")")

        # Round-trip self-test so you know NBFS actually runs.
        try:
            st, enc = run_nbfs(OP_ENCODE, str_to_jbytes("<Test/>"))
            if st == "ok":
                st2, dec = run_nbfs(OP_DECODE, enc)
                good = (st2 == "ok" and "<Test" in str(jbytes_to_str(dec)))
                print("NBFS self-test  :", "PASS" if good else "CHECK OUTPUT")
                if not good:
                    print("   decode returned:", jbytes_to_str(dec) if st2 == "ok" else dec)
            else:
                print("NBFS self-test  : FAILED to run ->", enc)
                print("   Fix NBFS_PATH / NBFS_INVOCATION above and reload.")
        except Exception as e:
            print("NBFS self-test  : ERROR ->", str(e))
        print("Open a msbin1 request in Repeater and use the '%s' tab." % TAB_CAPTION)

    def createNewInstance(self, controller, editable):
        return WCFTab(self, controller, editable)

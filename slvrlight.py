# -*- coding: utf-8 -*-
#
# Burp (Jython) extension: decode Silverlight/WCF bodies sent as
# Content-Type: application/x-zip  (zlib/deflate-compressed SOAP).
#
# Pipeline per body:
#   1. inflate:  zlib -> raw deflate -> gzip  (first that works wins)
#   2. inspect the inflated bytes:
#        - starts with '<'      -> text SOAP/XML, pretty-print
#        - looks like msbin1     -> shell out to NBFS.exe (optional)
#        - otherwise             -> hex dump so you always see something
#
# Read-only viewer tab. Set NBFS_EXE only if the inner layer is msbin1;
# if the inner layer is plain XML you don't need it at all.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.util import Arrays
from java.util.zip import Inflater, GZIPInputStream
from java.io import ByteArrayInputStream, ByteArrayOutputStream
import jarray
import subprocess
import base64
import os

# ---- Configure (only needed if the INNER layer turns out to be msbin1) ------
NBFS_EXE = r"C:\tools\wcf\NBFS.exe"
# Content-Type substrings that switch this tab on:
TRIGGERS = ("x-zip", "x-gzip", "zip", "deflate", "msbin1")
# -----------------------------------------------------------------------------


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        callbacks.setExtensionName("WCF x-zip / NBFS Decoder")
        callbacks.registerMessageEditorTabFactory(self)
        self._log("loaded. triggers=%s  NBFS=%s" %
                  (TRIGGERS, "present" if os.path.isfile(NBFS_EXE) else "absent (ok if inner is XML)"))

    def createNewInstance(self, controller, editable):
        return WcfTab(self)

    def _log(self, m):
        self._stdout.write((m + "\n").encode("utf-8"))


class WcfTab(IMessageEditorTab):
    def __init__(self, extender):
        self._x = extender
        self._helpers = extender._helpers
        self._txt = extender._callbacks.createTextEditor()
        self._txt.setEditable(False)
        self._current = None

    def getTabCaption(self):
        return "x-zip Decoded"

    def getUiComponent(self):
        return self._txt.getComponent()

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        info = (self._helpers.analyzeRequest(content) if isRequest
                else self._helpers.analyzeResponse(content))
        for h in info.getHeaders():
            hl = h.lower()
            if hl.startswith("content-type:") and any(t in hl for t in TRIGGERS):
                return True
        return False

    def setMessage(self, content, isRequest):
        self._current = content
        if content is None:
            self._txt.setText(None)
            return
        info = (self._helpers.analyzeRequest(content) if isRequest
                else self._helpers.analyzeResponse(content))
        body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
        if len(body) == 0:
            self._txt.setText(self._helpers.stringToBytes("[empty body]"))
            return
        self._txt.setText(self._helpers.stringToBytes(self._render(body)))

    def getMessage(self):
        return self._current

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._txt.getSelectedText()

    # ---- decode chain ------------------------------------------------------

    def _render(self, body):
        inner, how = self._inflate(body)
        if inner is None:
            # not compressed after all -> maybe it's msbin1 straight up
            inner, how = body, "not-compressed"

        if self._looks_xml(inner):
            return "[%s -> XML]\n\n%s" % (how, self._pretty_xml(inner))

        # not XML: try msbin1 via NBFS.exe if available
        if os.path.isfile(NBFS_EXE):
            xml = self._nbfs(inner)
            if xml is not None:
                return "[%s -> msbin1 -> XML]\n\n%s" % (how, xml)

        return ("[%s -> unknown inner format; showing hex]\n"
                "[first bytes: %s]\n\n%s" %
                (how, self._first_bytes(inner), self._hex(inner)))

    def _inflate(self, data):
        # returns (inflated_bytes, label) or (None, None)
        for nowrap, label in ((False, "zlib"), (True, "raw-deflate")):
            try:
                out = self._run_inflater(data, nowrap)
                if out and len(out) > 0:
                    return out, label
            except Exception:
                pass
        try:
            out = self._gunzip(data)
            if out and len(out) > 0:
                return out, "gzip"
        except Exception:
            pass
        return None, None

    def _run_inflater(self, data, nowrap):
        inf = Inflater(nowrap)
        inf.setInput(data)
        out = ByteArrayOutputStream()
        buf = jarray.zeros(8192, 'b')
        while not inf.finished():
            n = inf.inflate(buf)
            if n > 0:
                out.write(buf, 0, n)
            else:
                if inf.finished() or inf.needsDictionary() or inf.needsInput():
                    break
        inf.end()
        return out.toByteArray()

    def _gunzip(self, data):
        gz = GZIPInputStream(ByteArrayInputStream(data))
        out = ByteArrayOutputStream()
        buf = jarray.zeros(8192, 'b')
        while True:
            n = gz.read(buf)
            if n < 0:
                break
            out.write(buf, 0, n)
        gz.close()
        return out.toByteArray()

    # ---- helpers -----------------------------------------------------------

    def _looks_xml(self, data):
        i = 0
        # skip UTF-8 BOM
        if len(data) >= 3 and (data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF) == (0xEF, 0xBB, 0xBF):
            i = 3
        while i < len(data) and (data[i] & 0xFF) in (0x20, 0x09, 0x0A, 0x0D):
            i += 1
        return i < len(data) and (data[i] & 0xFF) == 0x3C  # '<'

    def _pretty_xml(self, data):
        s = self._helpers.bytesToString(data)
        try:
            from xml.dom import minidom
            p = minidom.parseString(s.encode("utf-8")).toprettyxml(indent="  ")
            return "\n".join(l for l in p.splitlines() if l.strip())
        except Exception:
            return s

    def _nbfs(self, data):
        try:
            b64 = str(self._helpers.base64Encode(data))
            p = subprocess.Popen([NBFS_EXE, "decode", b64],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            out = (out or "").strip()
            if not out:
                return None
            xml = base64.b64decode(out).decode("utf-8", "replace")
            if xml.lstrip().startswith("<"):
                return self._pretty_xml(self._helpers.stringToBytes(xml))
            return None
        except Exception:
            return None

    def _first_bytes(self, data, n=8):
        return " ".join("%02X" % (data[i] & 0xFF) for i in range(min(n, len(data))))

    def _hex(self, data, width=16, maxlen=4096):
        rows = []
        end = min(len(data), maxlen)
        for off in range(0, end, width):
            chunk = data[off:off + width]
            hexpart = " ".join("%02X" % (b & 0xFF) for b in chunk)
            asciip = "".join(chr(b & 0xFF) if 32 <= (b & 0xFF) < 127 else "." for b in chunk)
            rows.append("%08X  %-*s  %s" % (off, width * 3, hexpart, asciip))
        if len(data) > maxlen:
            rows.append("... (%d more bytes)" % (len(data) - maxlen))
        return "\n".join(rows)

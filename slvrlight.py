# -*- coding: utf-8 -*-
# Burp (Jython) extension: decode Silverlight/WCF application/x-zip bodies
# (zlib/deflate-compressed SOAP), with defensive error reporting so the tab
# never comes back silently empty.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.util import Arrays
from java.util.zip import Inflater, GZIPInputStream
from java.io import ByteArrayInputStream, ByteArrayOutputStream
import jarray
import subprocess
import base64
import os
import traceback

NBFS_EXE = r"C:\tools\wcf\NBFS.exe"
TRIGGERS = ("x-zip", "x-gzip", "zip", "deflate", "msbin1")


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        callbacks.setExtensionName("WCF x-zip / NBFS Decoder")
        callbacks.registerMessageEditorTabFactory(self)
        self._log("loaded ok. NBFS=%s" % ("present" if os.path.isfile(NBFS_EXE) else "absent"))

    def createNewInstance(self, controller, editable):
        return WcfTab(self)

    def _log(self, m):
        try:
            self._stdout.write((m + "\n").encode("utf-8"))
        except Exception:
            pass


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
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            for h in info.getHeaders():
                hl = h.lower()
                if hl.startswith("content-type:") and any(t in hl for t in TRIGGERS):
                    return True
        except Exception:
            return False
        return False

    def setMessage(self, content, isRequest):
        self._current = content
        if content is None:
            self._txt.setText(None)
            return
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            text = self._render(body)
        except Exception:
            text = "[extension crashed in setMessage]\n\n" + traceback.format_exc()
        if not text:
            text = "[render produced no text]"
        self._x._log(text)  # also echo to the extension output tab
        self._txt.setText(self._helpers.stringToBytes(text))

    def getMessage(self):
        return self._current

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._txt.getSelectedText()

    # ---- decode chain, each stage guarded ---------------------------------

    def _render(self, body):
        out = []
        out.append("[body %d bytes]  first: %s" % (len(body), self._first_bytes(body)))
        if len(body) == 0:
            return "\n".join(out + ["[empty body]"])

        inner, how = None, None
        try:
            inner, how = self._inflate(body)
        except Exception:
            out.append("[inflate raised]\n" + traceback.format_exc())

        if inner is None:
            inner, how = body, "not-compressed"
        out.append("[stage: %s]  inner %d bytes  first: %s" %
                   (how, len(inner), self._first_bytes(inner)))
        out.append("")

        try:
            if self._looks_xml(inner):
                out.append(self._pretty_xml(inner))
                return "\n".join(out)
        except Exception:
            out.append("[xml stage raised]\n" + traceback.format_exc())

        if os.path.isfile(NBFS_EXE):
            try:
                xml = self._nbfs(inner)
                if xml is not None:
                    out.append(xml)
                    return "\n".join(out)
            except Exception:
                out.append("[nbfs stage raised]\n" + traceback.format_exc())

        out.append("[inner not XML / no msbin1 decode -- hex dump]")
        out.append(self._hex(inner))
        return "\n".join(out)

    def _inflate(self, data):
        for nowrap, label in ((False, "zlib"), (True, "raw-deflate")):
            try:
                o = self._run_inflater(data, nowrap)
                if o and len(o) > 0:
                    return o, label
            except Exception:
                pass
        try:
            o = self._gunzip(data)
            if o and len(o) > 0:
                return o, "gzip"
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
            elif inf.finished() or inf.needsDictionary() or inf.needsInput():
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

    # ---- helpers (no java-array slicing) ----------------------------------

    def _looks_xml(self, data):
        i = 0
        if (len(data) >= 3 and (data[0] & 0xFF) == 0xEF
                and (data[1] & 0xFF) == 0xBB and (data[2] & 0xFF) == 0xBF):
            i = 3
        while i < len(data) and (data[i] & 0xFF) in (0x20, 0x09, 0x0A, 0x0D):
            i += 1
        return i < len(data) and (data[i] & 0xFF) == 0x3C

    def _pretty_xml(self, data):
        s = self._helpers.bytesToString(data)
        try:
            from xml.dom import minidom
            p = minidom.parseString(s.encode("utf-8")).toprettyxml(indent="  ")
            return "\n".join(l for l in p.splitlines() if l.strip())
        except Exception:
            return s

    def _nbfs(self, data):
        b64 = str(self._helpers.base64Encode(data))
        p = subprocess.Popen([NBFS_EXE, "decode", b64],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        so, se = p.communicate()
        so = (so or "").strip()
        if not so:
            return None
        xml = base64.b64decode(so).decode("utf-8", "replace")
        if xml.lstrip().startswith("<"):
            return self._pretty_xml(self._helpers.stringToBytes(xml))
        return None

    def _first_bytes(self, data, n=8):
        return " ".join("%02X" % (data[i] & 0xFF) for i in range(min(n, len(data))))

    def _hex(self, data, width=16, maxlen=8192):
        rows = []
        end = min(len(data), maxlen)
        off = 0
        while off < end:
            hexp, asc = [], []
            j = off
            while j < off + width and j < end:
                v = data[j] & 0xFF
                hexp.append("%02X" % v)
                asc.append(chr(v) if 32 <= v < 127 else ".")
                j += 1
            rows.append("%08X  %-48s  %s" % (off, " ".join(hexp), "".join(asc)))
            off += width
        if len(data) > maxlen:
            rows.append("... (%d more bytes)" % (len(data) - maxlen))
        return "\n".join(rows)

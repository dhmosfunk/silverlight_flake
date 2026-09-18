# -*- coding: utf-8 -*-
# Burp (Jython): decode AND edit Silverlight/WCF x-zip (zlib) / msbin1 requests.
# - shows editable decoded XML in the "x-zip Edit" tab
# - on Send/Forward, re-encodes: [msbin1 encode if needed] -> compress -> fix length
# Works in Repeater and Proxy intercept (editable contexts). History is read-only.

from burp import (IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab,
                  IHttpListener)
from java.util import Arrays
from java.util.zip import Inflater, GZIPInputStream, Deflater, GZIPOutputStream
from java.io import ByteArrayInputStream, ByteArrayOutputStream, PrintWriter
from java.lang import String as JString
import jarray
import subprocess
import os
import traceback

NBFS_EXE = r"C:\tools\wcf\NBFS.exe"          # only needed if inner layer is msbin1
TRIGGERS = ("x-zip", "x-gzip", "zip", "deflate", "msbin1")


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("WCF x-zip / msbin1 Editor")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)
        self.log("=== WCF x-zip / msbin1 Editor loaded. NBFS=%s ===" %
                 ("present" if os.path.isfile(NBFS_EXE) else "absent (ok if inner is XML)"))

    def log(self, m):
        try:
            self._out.println(m)
        except Exception:
            pass

    def createNewInstance(self, controller, editable):
        return WcfEditTab(self, editable)

    # visibility only: log decoded bodies of live traffic to Output
    def processHttpMessage(self, toolFlag, isReq, mi):
        try:
            raw = mi.getRequest() if isReq else mi.getResponse()
            if raw is None:
                return
            info = (self._helpers.analyzeRequest(raw) if isReq
                    else self._helpers.analyzeResponse(raw))
            ct = self._content_type(info.getHeaders())
            if not ct or not any(t in ct.lower() for t in TRIGGERS):
                return
            body = Arrays.copyOfRange(raw, info.getBodyOffset(), len(raw))
            inner, how, kind, xml = self.decode(body)
            self.log("\n---- %s (%s) [%s/%s] ----\n%s"
                     % ("REQUEST" if isReq else "RESPONSE", ct, how, kind, xml))
        except Exception:
            self.log("[listener] " + traceback.format_exc())

    # ===================== decode / encode core ============================

    def decode(self, body):
        """returns (inner_bytes, how, kind, display_text). kind in xml/msbin1/raw."""
        if len(body) == 0:
            return body, "none", "raw", "[empty body]"
        inner, how = self._inflate(body)
        if inner is None:
            inner, how = body, "none"
        if self._looks_xml(inner):
            return inner, how, "xml", self._pretty(self._helpers.bytesToString(inner))
        if os.path.isfile(NBFS_EXE):
            xml = self._nbfs_decode(inner)
            if xml is not None:
                return inner, how, "msbin1", self._pretty(xml)
        return inner, how, "raw", ("[cannot decode inner; how=%s first=%s]\n%s"
                                   % (how, self._first(inner), self._hex(inner)))

    def encode(self, xml_text, how, kind):
        """reverse of decode: xml text -> wire body bytes (java byte[]) or None."""
        if kind == "xml":
            inner = JString(xml_text).getBytes("UTF-8")
        elif kind == "msbin1":
            inner = self._nbfs_encode(xml_text)
            if inner is None:
                return None
        else:
            return None
        return self._compress(inner, how)

    # ---- compression ------------------------------------------------------

    def _inflate(self, data):
        for nowrap, label in ((False, "zlib"), (True, "raw-deflate")):
            try:
                inf = Inflater(nowrap); inf.setInput(data)
                out = ByteArrayOutputStream(); buf = jarray.zeros(8192, 'b')
                while not inf.finished():
                    n = inf.inflate(buf)
                    if n > 0:
                        out.write(buf, 0, n)
                    elif inf.finished() or inf.needsDictionary() or inf.needsInput():
                        break
                inf.end()
                b = out.toByteArray()
                if b and len(b) > 0:
                    return b, label
            except Exception:
                pass
        try:
            gz = GZIPInputStream(ByteArrayInputStream(data))
            out = ByteArrayOutputStream(); buf = jarray.zeros(8192, 'b')
            while True:
                n = gz.read(buf)
                if n < 0:
                    break
                out.write(buf, 0, n)
            gz.close()
            b = out.toByteArray()
            if b and len(b) > 0:
                return b, "gzip"
        except Exception:
            pass
        return None, None

    def _compress(self, data, how):
        if how in (None, "none"):
            return data
        if how == "gzip":
            bos = ByteArrayOutputStream()
            g = GZIPOutputStream(bos); g.write(data); g.close()
            return bos.toByteArray()
        nowrap = (how == "raw-deflate")
        d = Deflater(Deflater.DEFAULT_COMPRESSION, nowrap)
        d.setInput(data); d.finish()
        bos = ByteArrayOutputStream(); buf = jarray.zeros(8192, 'b')
        while not d.finished():
            n = d.deflate(buf)
            if n > 0:
                bos.write(buf, 0, n)
        d.end()
        return bos.toByteArray()

    # ---- msbin1 via NBFS.exe (stays in java byte[] via helpers.base64*) ----

    def _nbfs_decode(self, data):
        b64 = self._helpers.base64Encode(data)
        p = subprocess.Popen([NBFS_EXE, "decode", str(b64)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        so, se = p.communicate()
        so = (so or "").strip()
        if not so:
            return None
        xml_bytes = self._helpers.base64Decode(so)
        s = JString(xml_bytes, "UTF-8")
        return s if s.lstrip().startswith("<") else None

    def _nbfs_encode(self, xml_text):
        raw = JString(xml_text).getBytes("UTF-8")
        b64 = self._helpers.base64Encode(raw)
        p = subprocess.Popen([NBFS_EXE, "encode", str(b64)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        so, se = p.communicate()
        so = (so or "").strip()
        if not so:
            self.log("[nbfs encode: no output] " + (se or ""))
            return None
        return self._helpers.base64Decode(so)   # java byte[] msbin1

    # ---- helpers ----------------------------------------------------------

    def _content_type(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                return h.split(":", 1)[1].strip()
        return None

    def _looks_xml(self, data):
        i = 0
        if (len(data) >= 3 and (data[0] & 0xFF) == 0xEF
                and (data[1] & 0xFF) == 0xBB and (data[2] & 0xFF) == 0xBF):
            i = 3
        while i < len(data) and (data[i] & 0xFF) in (0x20, 0x09, 0x0A, 0x0D):
            i += 1
        return i < len(data) and (data[i] & 0xFF) == 0x3C

    def _pretty(self, s):
        try:
            from xml.dom import minidom
            p = minidom.parseString(JString(s).getBytes("UTF-8")).toprettyxml(indent="  ")
            return "\n".join(l for l in p.splitlines() if l.strip())
        except Exception:
            return s if isinstance(s, (str, unicode)) else str(s)

    def _first(self, data, n=8):
        return " ".join("%02X" % (data[i] & 0xFF) for i in range(min(n, len(data))))

    def _hex(self, data, width=16, maxlen=4096):
        rows = []; end = min(len(data), maxlen); off = 0
        while off < end:
            hexp, asc = [], []; j = off
            while j < off + width and j < end:
                v = data[j] & 0xFF
                hexp.append("%02X" % v)
                asc.append(chr(v) if 32 <= v < 127 else ".")
                j += 1
            rows.append("%08X  %-48s  %s" % (off, " ".join(hexp), "".join(asc)))
            off += width
        return "\n".join(rows)


class WcfEditTab(IMessageEditorTab):
    def __init__(self, extender, editable):
        self._x = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._txt = extender._callbacks.createTextEditor()
        self._txt.setEditable(editable)
        self._current = None
        self._isReq = True
        self._how = "none"
        self._kind = "raw"

    def getTabCaption(self):
        return "x-zip Edit"

    def getUiComponent(self):
        return self._txt.getComponent()

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            ct = self._x._content_type(info.getHeaders())
            return bool(ct and any(t in ct.lower() for t in TRIGGERS))
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self._current = content
        self._isReq = isRequest
        if content is None:
            self._txt.setText(None)
            return
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            inner, how, kind, xml = self._x.decode(body)
            self._how, self._kind = how, kind
            # only allow editing when we can faithfully re-encode
            self._txt.setEditable(self._editable and kind in ("xml", "msbin1"))
            self._txt.setText(JString(xml).getBytes("UTF-8"))
        except Exception:
            self._txt.setEditable(False)
            self._txt.setText(JString("[decode failed]\n" + traceback.format_exc()).getBytes("UTF-8"))

    def isModified(self):
        return self._txt.isTextModified()

    def getMessage(self):
        try:
            if (not self._editable or self._current is None
                    or self._kind not in ("xml", "msbin1")
                    or not self._txt.isTextModified()):
                return self._current
            text = JString(self._txt.getText(), "UTF-8")
            body = self._x.encode(text, self._how, self._kind)
            if body is None:
                return self._current
            info = (self._helpers.analyzeRequest(self._current) if self._isReq
                    else self._helpers.analyzeResponse(self._current))
            return self._helpers.buildHttpMessage(info.getHeaders(), body)
        except Exception:
            self._x.log("[getMessage] " + traceback.format_exc())
            return self._current

    def getSelectedData(self):
        return self._txt.getSelectedText()

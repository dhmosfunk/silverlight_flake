# -*- coding: utf-8 -*-
# Burp (Jython): decode Silverlight/WCF bodies (application/x-zip zlib-compressed,
# and application/soap+msbin1). Prints decoded bodies to the Extensions Output tab
# via a PrintWriter (reliable), and also provides a message-editor tab.

from burp import (IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab,
                  IHttpListener)
from java.util import Arrays
from java.util.zip import Inflater, GZIPInputStream
from java.io import (ByteArrayInputStream, ByteArrayOutputStream, PrintWriter)
import jarray
import subprocess
import base64
import os
import traceback

NBFS_EXE = r"C:\tools\wcf\NBFS.exe"
TRIGGERS = ("x-zip", "x-gzip", "zip", "deflate", "msbin1")
SAVE_DIR = None    # e.g. r"C:\tools\wcf\dumps" to also save decoded messages to files


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # PrintWriter with autoflush -- THIS is what makes Output actually print
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._err = PrintWriter(callbacks.getStderr(), True)
        self._n = 0
        callbacks.setExtensionName("WCF x-zip / NBFS Decoder")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)
        self.log("=========================================================")
        self.log(" WCF x-zip / NBFS Decoder loaded OK")
        self.log(" NBFS.exe: %s" % ("present" if os.path.isfile(NBFS_EXE) else "absent (fine if bodies are XML)"))
        self.log(" Watching content-types containing: %s" % ", ".join(TRIGGERS))
        self.log(" NOTE: the listener only fires on NEW traffic through Burp.")
        self.log("       Send a request in Repeater or reload the app to test.")
        self.log("=========================================================")

    def log(self, m):
        try:
            self._out.println(m)
        except Exception:
            try:
                self._out.println(repr(m))
            except Exception:
                pass

    def createNewInstance(self, controller, editable):
        return WcfTab(self)

    # ---- HTTP listener: reliable output channel ---------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                raw = messageInfo.getRequest()
                if raw is None:
                    return
                info = self._helpers.analyzeRequest(raw)
                kind = "REQUEST"
            else:
                raw = messageInfo.getResponse()
                if raw is None:
                    return
                info = self._helpers.analyzeResponse(raw)
                kind = "RESPONSE"

            ctype = self._content_type(info.getHeaders())
            if not ctype or not any(t in ctype.lower() for t in TRIGGERS):
                return

            body = Arrays.copyOfRange(raw, info.getBodyOffset(), len(raw))
            self._n += 1
            url = ""
            try:
                url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
            except Exception:
                pass

            decoded = self.decode_body(body)
            self.log("\n================ #%d %s  (%s) ================"
                     % (self._n, kind, ctype))
            if url:
                self.log(url)
            self.log(decoded)

            if SAVE_DIR:
                self._save(decoded, kind)
        except Exception:
            self.log("[listener error]\n" + traceback.format_exc())

    def _save(self, decoded, kind):
        try:
            if not os.path.isdir(SAVE_DIR):
                os.makedirs(SAVE_DIR)
            fn = os.path.join(SAVE_DIR, "msg_%04d_%s.txt" % (self._n, kind.lower()))
            f = open(fn, "wb")
            f.write(decoded.encode("utf-8", "replace"))
            f.close()
        except Exception:
            self.log("[save failed]\n" + traceback.format_exc())

    # ---- shared decode logic ----------------------------------------------

    def decode_body(self, body):
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
        out.append("[stage: %s]  inner %d bytes  first: %s"
                   % (how, len(inner), self._first_bytes(inner)))
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

    def _content_type(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                return h.split(":", 1)[1].strip()
        return None

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
            ct = self._x._content_type(info.getHeaders())
            return bool(ct and any(t in ct.lower() for t in TRIGGERS))
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self._x.log("[tab] setMessage fired isRequest=%s len=%s"
                    % (isRequest, "None" if content is None else len(content)))
        self._current = content
        if content is None:
            self._txt.setText(None)
            return
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            text = self._x.decode_body(body)
        except Exception:
            text = "[tab crashed]\n\n" + traceback.format_exc()
        if not text:
            text = "[no text produced]"
        try:
            self._txt.setText(self._helpers.stringToBytes(text))
        except Exception:
            self._x.log("[tab setText failed]\n" + traceback.format_exc())

    def getMessage(self):
        return self._current

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._txt.getSelectedText()

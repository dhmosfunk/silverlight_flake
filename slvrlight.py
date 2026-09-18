# -*- coding: utf-8 -*-
# Burp (Jython): "NBFS Decoded" tab in the Repeater/Proxy request-response viewer.
# Decodes application/soap+msbin1 bodies via NBFS.exe (Java ProcessBuilder).
# Renders into a plain JTextArea (reliable) instead of Burp's text editor.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JScrollPane, JTextArea
from java.awt import Font
from java.util import Arrays, ArrayList
from java.lang import ProcessBuilder, String as JString
from java.io import BufferedReader, InputStreamReader
import os
import traceback

NBFS_EXE = r"C:\tools\wcf\NBFS.exe"
TRIGGERS = ("msbin1",)


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("NBFS msbin1 (Repeater tab)")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.printOutput("NBFS Repeater tab loaded. NBFS.exe %s"
                              % ("FOUND" if os.path.isfile(NBFS_EXE) else "MISSING at " + NBFS_EXE))

    def createNewInstance(self, controller, editable):
        return NbfsTab(self)

    # ---- shared logic ------------------------------------------------------

    def is_msbin1(self, headers):
        for h in headers:
            hl = h.lower()
            if hl.startswith("content-type:") and any(t in hl for t in TRIGGERS):
                return True
        return False

    def nbfs_decode(self, body):
        if body is None or len(body) == 0:
            return "[empty body]"
        if not os.path.isfile(NBFS_EXE):
            return "[NBFS.exe not found at %s]" % NBFS_EXE
        try:
            b64 = self._helpers.base64Encode(body)     # java String
            cmd = ArrayList()
            cmd.add(NBFS_EXE); cmd.add("decode"); cmd.add(b64)
            proc = ProcessBuilder(cmd).start()
            out = self._read(proc.getInputStream())
            err = self._read(proc.getErrorStream())
            proc.waitFor()
            out = out.strip()
            if not out:
                return "[NBFS.exe returned nothing] " + err
            # base64Decode -> java.lang.String -> convert to python unicode
            xml = unicode(JString(self._helpers.base64Decode(out), "UTF-8"))
            if not xml.lstrip().startswith("<"):
                return "[NBFS decode error / not XML]\n" + xml
            return self._pretty(xml)
        except Exception:
            return "[nbfs_decode raised]\n" + traceback.format_exc()

    def _read(self, stream):
        br = BufferedReader(InputStreamReader(stream, "UTF-8"))
        parts = []
        line = br.readLine()
        while line is not None:
            parts.append(line)
            line = br.readLine()
        br.close()
        return "".join(parts)

    def _pretty(self, xml):
        # xml is a python unicode here
        try:
            from xml.dom import minidom
            p = minidom.parseString(xml.encode("utf-8")).toprettyxml(indent="  ")
            return "\n".join(l for l in p.splitlines() if l.strip())
        except Exception:
            return xml


class NbfsTab(IMessageEditorTab):

    def __init__(self, extender):
        self._x = extender
        self._helpers = extender._helpers
        self._area = JTextArea()
        self._area.setEditable(False)
        self._area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._scroll = JScrollPane(self._area)
        self._current = None

    def getTabCaption(self):
        return "NBFS Decoded"

    def getUiComponent(self):
        return self._scroll

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            return self._x.is_msbin1(info.getHeaders())
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self._current = content
        if content is None:
            self._area.setText("")
            return
        try:
            info = (self._helpers.analyzeRequest(content) if isRequest
                    else self._helpers.analyzeResponse(content))
            body = Arrays.copyOfRange(content, info.getBodyOffset(), len(content))
            text = "[%s msbin1 body %d bytes]\n\n%s" % (
                "REQUEST" if isRequest else "RESPONSE", len(body),
                self._x.nbfs_decode(body))
        except Exception:
            text = "[tab error]\n" + traceback.format_exc()
        self._area.setText(text)
        self._area.setCaretPosition(0)

    def getMessage(self):
        return self._current

    def isModified(self):
        return False

    def getSelectedData(self):
        s = self._area.getSelectedText()
        return self._helpers.stringToBytes(s) if s else None

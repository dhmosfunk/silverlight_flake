# -*- coding: utf-8 -*-
#
# Burp Suite (Jython) extension: view WCF Binary SOAP (application/soap+msbin1)
# request/response bodies as decoded XML.
#
# Engine: shells out to NBFS.exe (built from GDSSecurity/WCF-Binary-SOAP-Plug-In's
# NBFS.cs). This is read-only: it decodes for viewing. Editing/re-encoding to send
# modified messages is a separate problem (see notes at bottom).
#
# Setup:
#   1. Build NBFS.exe:  csc /target:exe /out:NBFS.exe NBFS.cs
#   2. Set NBFS_EXE below to its full path.
#   3. Burp -> Extensions -> Add -> Extension type: Python -> select this file.
#      (Jython standalone JAR must be configured in Burp's Python environment.)

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.util import Arrays
import subprocess
import base64
import os

# ---- Configure this ---------------------------------------------------------
NBFS_EXE = r"C:\tools\wcf\NBFS.exe"
# -----------------------------------------------------------------------------


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        callbacks.setExtensionName("NBFS (msbin1) Decoder")
        callbacks.registerMessageEditorTabFactory(self)
        if not os.path.isfile(NBFS_EXE):
            self._log("WARNING: NBFS_EXE not found at %s -- decoding will fail." % NBFS_EXE)
        else:
            self._log("NBFS decoder ready (%s)" % NBFS_EXE)

    def createNewInstance(self, controller, editable):
        # editable=False -> we present a read-only viewer, never mutate the message
        return NBFSTab(self, controller)

    def _log(self, msg):
        self._stdout.write((msg + "\n").encode("utf-8"))


class NBFSTab(IMessageEditorTab):

    def __init__(self, extender, controller):
        self._extender = extender
        self._helpers = extender._helpers
        self._txt = extender._callbacks.createTextEditor()
        self._txt.setEditable(False)
        self._current = None

    def getTabCaption(self):
        return "NBFS Decoded"

    def getUiComponent(self):
        return self._txt.getComponent()

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        info = (self._helpers.analyzeRequest(content) if isRequest
                else self._helpers.analyzeResponse(content))
        for h in info.getHeaders():
            hl = h.lower()
            if hl.startswith("content-type:") and "msbin1" in hl:
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
        b64 = str(self._helpers.base64Encode(body))
        try:
            xml = self._decode(b64)
        except Exception as e:
            xml = "[decode error] %s" % e
        self._txt.setText(self._helpers.stringToBytes(xml))

    def getMessage(self):
        return self._current          # read-only: hand back the original untouched

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._txt.getSelectedText()

    # --- decoding -----------------------------------------------------------

    def _decode(self, b64input):
        # NBFS.exe decode <base64>  ->  base64(UTF-8 XML) on stdout
        p = subprocess.Popen(
            [NBFS_EXE, "decode", b64input],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        out = (out or "").strip()
        if not out:
            return "[no output from NBFS.exe] %s" % (err or "")
        try:
            xml = base64.b64decode(out).decode("utf-8", "replace")
        except Exception:
            # NBFS.exe returns exceptions as base64 too; if that fails, show raw
            return "[unexpected NBFS output] %s" % out
        return self._pretty(xml)

    def _pretty(self, xml):
        try:
            from xml.dom import minidom
            pretty = minidom.parseString(xml.encode("utf-8")).toprettyxml(indent="  ")
            # strip blank lines minidom loves to add
            return "\n".join(l for l in pretty.splitlines() if l.strip())
        except Exception:
            return xml

# -*- coding: utf-8 -*-
# Burp (Jython): decode WCF msbin1 via a RIGHT-CLICK menu + popup window,
# not a message-editor tab. Uses NBFS.exe through Java ProcessBuilder.

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (JMenuItem, JScrollPane, JTextArea, JFrame,
                         SwingUtilities, JPanel)
from java.awt import BorderLayout, Font, Dimension
from java.util import ArrayList, Arrays
from java.lang import ProcessBuilder, String as JString, Runnable
from java.io import BufferedReader, InputStreamReader
import os
import traceback

NBFS_EXE = r"C:\tools\wcf\NBFS.exe"


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._inv = None
        callbacks.setExtensionName("NBFS msbin1 (menu)")
        callbacks.registerContextMenuFactory(self)
        # top-level "NBFS" tab that accumulates results
        self._area = JTextArea()
        self._area.setEditable(False)
        self._area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._area), BorderLayout.CENTER)
        callbacks.addSuiteTab(self)
        self._print("NBFS msbin1 (menu) loaded. NBFS.exe %s"
                    % ("FOUND" if os.path.isfile(NBFS_EXE) else "MISSING at " + NBFS_EXE))

    # ITab
    def getTabCaption(self):
        return "NBFS"

    def getUiComponent(self):
        return self._panel

    # IContextMenuFactory
    def createMenuItems(self, invocation):
        self._inv = invocation
        item = JMenuItem("Decode msbin1 (NBFS)", actionPerformed=self._on_click)
        items = ArrayList()
        items.add(item)
        return items

    def _on_click(self, event):
        try:
            inv = self._inv
            ctx = inv.getInvocationContext()
            msgs = inv.getSelectedMessages()
            if not msgs:
                self._popup("NBFS", "[no message selected]")
                return
            chunks = []
            for m in msgs:
                chunks.append(self._decode_one(m, ctx))
            text = ("\n\n" + "=" * 70 + "\n\n").join(chunks)
            self._append(text)
            self._popup("NBFS decoded", text)
        except Exception:
            self._popup("NBFS error", traceback.format_exc())

    def _decode_one(self, m, ctx):
        # ctx: 0/2 = request, 1/3 = response; else try response then request
        try:
            if ctx in (0, 2):
                raw, isReq = m.getRequest(), True
            elif ctx in (1, 3):
                raw, isReq = m.getResponse(), False
            else:
                raw, isReq = (m.getResponse(), False) if m.getResponse() else (m.getRequest(), True)
            if raw is None:
                return "[no bytes for this message]"
            info = (self._helpers.analyzeRequest(raw) if isReq
                    else self._helpers.analyzeResponse(raw))
            body = Arrays.copyOfRange(raw, info.getBodyOffset(), len(raw))
            head = "[%s body %d bytes]" % ("REQUEST" if isReq else "RESPONSE", len(body))
            return head + "\n\n" + self._nbfs_decode(body)
        except Exception:
            return "[decode_one error]\n" + traceback.format_exc()

    def _nbfs_decode(self, body):
        if body is None or len(body) == 0:
            return "[empty body]"
        if not os.path.isfile(NBFS_EXE):
            return "[NBFS.exe not found at %s]" % NBFS_EXE
        try:
            b64 = self._helpers.base64Encode(body)   # java String
            cmd = ArrayList()
            cmd.add(NBFS_EXE); cmd.add("decode"); cmd.add(b64)
            pb = ProcessBuilder(cmd)
            proc = pb.start()
            out = self._read(proc.getInputStream())
            err = self._read(proc.getErrorStream())
            proc.waitFor()
            out = out.strip()
            if not out:
                return "[NBFS.exe returned nothing] " + err
            xml = JString(self._helpers.base64Decode(out), "UTF-8")
            if not xml.lstrip().startswith("<"):
                return "[NBFS decode error] " + xml
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
        return "".join(parts)   # base64 is one token; join without newlines

    def _pretty(self, xml):
        try:
            from xml.dom import minidom
            p = minidom.parseString(JString(xml).getBytes("UTF-8")).toprettyxml(indent="  ")
            return "\n".join(l for l in p.splitlines() if l.strip())
        except Exception:
            return xml if isinstance(xml, (str, unicode)) else str(xml)

    # ---- UI helpers --------------------------------------------------------

    def _append(self, text):
        area = self._area
        class _R(Runnable):
            def run(_s):
                area.append(text + "\n\n" + ("#" * 70) + "\n\n")
                area.setCaretPosition(area.getDocument().getLength())
        SwingUtilities.invokeLater(_R())

    def _popup(self, title, text):
        class _R(Runnable):
            def run(_s):
                f = JFrame(title)
                ta = JTextArea(text)
                ta.setEditable(False)
                ta.setFont(Font("Monospaced", Font.PLAIN, 12))
                f.add(JScrollPane(ta))
                f.setSize(Dimension(950, 720))
                f.setLocationRelativeTo(None)
                f.setVisible(True)
        SwingUtilities.invokeLater(_R())

    def _print(self, m):
        try:
            self._callbacks.printOutput(m)
        except Exception:
            pass

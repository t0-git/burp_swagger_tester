# -*- coding: utf-8 -*-
# SwaggerJWTTester - Burp Suite Extension
# Loads a Swagger/OpenAPI JSON, lets you modify URLs, params, and send
# requests with multiple JWTs, displaying results in a grid.
#
# Installation:
#   1. Ensure Jython standalone JAR is configured in Burp (Extender > Options > Python Environment)
#   2. Go to Extender > Extensions > Add
#   3. Extension type: Python
#   4. Select this file
#
# Usage:
#   1. Go to the "Swagger JWT Tester" tab
#   2. Click "Load Swagger JSON" to load your OpenAPI/Swagger file
#   3. Set the Base URL override if needed
#   4. Select an endpoint from the dropdown
#   5. Edit parameters in the parameter table
#   6. Add one or more JWTs in the JWT panel
#   7. Click "Send Requests" — one request per JWT
#   8. Click any row in the results table to view the full response

from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTextArea, JScrollPane,
    JTable, JComboBox, JFileChooser, JSplitPane, BorderFactory,
    JOptionPane, SwingUtilities, BoxLayout, Box, JTabbedPane,
    JProgressBar
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import TitledBorder
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt import FlowLayout, Dimension, Color, Font, GridLayout
from java.awt.event import ActionListener, MouseAdapter
from java.io import File
from java.lang import Runnable, String, Thread as JThread
import java.net
import json
import traceback


# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_file(path):
    with open(path, "r") as f:
        return f.read()


def _resolve_ref(spec, ref):
    """Walk a $ref like '#/definitions/Foo' or '#/components/schemas/Foo'."""
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        node = node.get(p, {})
    return node


def _extract_params(spec, path_item, operation):
    """Return a list of dicts: {name, in, type, required, default, description}."""
    params = []
    seen = set()
    for p in list(path_item.get("parameters", [])) + list(operation.get("parameters", [])):
        if "$ref" in p:
            p = _resolve_ref(spec, p["$ref"])
        key = (p.get("name"), p.get("in"))
        if key in seen:
            continue
        seen.add(key)
        schema = p.get("schema", {})
        params.append({
            "name": p.get("name", ""),
            "in": p.get("in", "query"),
            "type": schema.get("type", p.get("type", "string")),
            "required": p.get("required", False),
            "default": schema.get("default", p.get("default", "")),
            "description": p.get("description", ""),
        })

    # Also extract request body fields for OpenAPI 3.x
    req_body = operation.get("requestBody", {})
    if req_body:
        content = req_body.get("content", {})
        json_schema = content.get("application/json", {}).get("schema", {})
        if "$ref" in json_schema:
            json_schema = _resolve_ref(spec, json_schema["$ref"])
        for prop_name, prop_val in json_schema.get("properties", {}).items():
            params.append({
                "name": prop_name,
                "in": "body",
                "type": prop_val.get("type", "string"),
                "required": prop_name in json_schema.get("required", []),
                "default": prop_val.get("default", ""),
                "description": prop_val.get("description", ""),
            })
    return params


def _build_endpoints(spec):
    """Return list of (label, method, path, params)."""
    endpoints = []
    base = ""
    # Swagger 2.0
    if "basePath" in spec:
        base = spec.get("basePath", "").rstrip("/")
    # OpenAPI 3.x servers
    elif "servers" in spec:
        first = spec["servers"][0].get("url", "")
        # If it's a relative path, keep it; absolute URL will be overridden.
        if first.startswith("/"):
            base = first.rstrip("/")

    paths = spec.get("paths", {})
    for path, path_item in sorted(paths.items()):
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method in path_item:
                operation = path_item[method]
                full_path = base + path
                label = "%s %s" % (method.upper(), full_path)
                params = _extract_params(spec, path_item, operation)
                endpoints.append((label, method.upper(), full_path, params))
    return endpoints


# ── Editable-column JTable (Jython-safe override) ─────────────────────────

class _EditableTable(JTable):
    """JTable where only specific columns are editable.
    Overriding isCellEditable on JTable is more reliable in Jython
    than overriding it on DefaultTableModel."""
    def __init__(self, model, editable_cols):
        JTable.__init__(self, model)
        self._editable = editable_cols  # list or set of column indices

    def isCellEditable(self, row, col):
        return col in self._editable


# ── Status code cell renderer ──────────────────────────────────────────────

class _StatusRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, selected, focused, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, col)
        try:
            code = int(value)
            if 200 <= code < 300:
                comp.setForeground(Color(0, 128, 0))
            elif 300 <= code < 400:
                comp.setForeground(Color(200, 150, 0))
            elif code >= 400:
                comp.setForeground(Color(200, 0, 0))
            else:
                comp.setForeground(Color.BLACK)
        except Exception:
            comp.setForeground(Color.BLACK)
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        return comp


# ── Main Extension ─────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, ITab, IMessageEditorController):

    # ── IBurpExtender ──────────────────────────────────────────────────────
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Swagger JWT Tester")

        self._spec = None
        self._endpoints = []
        self._responses = []     # response body string per row
        self._requests = []      # request text per row
        self._raw_requests = []  # raw request byte[] per row
        self._raw_responses = [] # full raw response byte[] per row
        self._http_services = [] # IHttpService per row
        self._currentRow = -1    # currently selected result row
        self._autoScanTabs = []  # list of per-endpoint tab data dicts

        SwingUtilities.invokeLater(self._buildUI)

    # ── ITab ───────────────────────────────────────────────────────────────
    def getTabCaption(self):
        return "Swagger JWT Tester"

    def getUiComponent(self):
        return self._mainPanel

    # ── IMessageEditorController ───────────────────────────────────────────
    def getHttpService(self):
        if 0 <= self._currentRow < len(self._http_services):
            return self._http_services[self._currentRow]
        return None

    def getRequest(self):
        if 0 <= self._currentRow < len(self._raw_requests):
            return self._raw_requests[self._currentRow]
        return None

    def getResponse(self):
        if 0 <= self._currentRow < len(self._raw_responses):
            return self._raw_responses[self._currentRow]
        return None

    # ── UI construction ────────────────────────────────────────────────────
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout(0, 4))
        self._mainPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # ══════════════════════════════════════════════════════════════════
        # Top-level tabbed pane: Configuration | Requests
        # ══════════════════════════════════════════════════════════════════
        self._topTabs = JTabbedPane()

        # ══════════════════════════════════════════════════════════════════
        #  TAB 1: CONFIGURATION
        # ══════════════════════════════════════════════════════════════════
        configTab = JPanel(BorderLayout(0, 4))
        configTab.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # ── Swagger load + Base URL + Session ────────────────────────────
        topPanel = JPanel(GridBagLayout())
        topPanel.setBorder(BorderFactory.createTitledBorder("Swagger / OpenAPI"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0
        topPanel.add(JLabel("Swagger JSON:"), gbc)

        self._filePathField = JTextField(40)
        self._filePathField.setEditable(False)
        gbc.gridx = 1; gbc.weightx = 1.0
        topPanel.add(self._filePathField, gbc)

        loadBtn = JButton("Load Swagger JSON", actionPerformed=self._onLoadSwagger)
        gbc.gridx = 2; gbc.weightx = 0
        topPanel.add(loadBtn, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0
        topPanel.add(JLabel("Base URL:"), gbc)

        self._baseUrlField = JTextField("https://api.example.com", 40)
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.gridwidth = 2
        topPanel.add(self._baseUrlField, gbc)
        gbc.gridwidth = 1

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0
        topPanel.add(JLabel("User-Agent:"), gbc)

        self._userAgentField = JTextField("SwaggerJWTTester-Burp/1.0", 40)
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.gridwidth = 2
        topPanel.add(self._userAgentField, gbc)
        gbc.gridwidth = 1

        # State save / load row
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0
        topPanel.add(JLabel("Session:"), gbc)

        stateRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        stateRow.add(JButton("Save State...", actionPerformed=self._onSaveState))
        stateRow.add(JButton("Load State...", actionPerformed=self._onLoadState))
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.gridwidth = 2
        topPanel.add(stateRow, gbc)
        gbc.gridwidth = 1

        configTab.add(topPanel, BorderLayout.NORTH)

        # ── Center: endpoint selector + params + JWTs ────────────────────
        centerPanel = JPanel(BorderLayout(0, 4))

        # Endpoint selector row
        endpointRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        endpointRow.add(JLabel("Endpoint:"))
        self._endpointCombo = JComboBox()
        self._endpointCombo.setPreferredSize(Dimension(600, 26))
        self._endpointCombo.addActionListener(lambda e: self._onEndpointChanged())
        endpointRow.add(self._endpointCombo)
        centerPanel.add(endpointRow, BorderLayout.NORTH)

        # Params + JWTs side by side
        configSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        configSplit.setResizeWeight(0.55)
        configSplit.setDividerSize(8)
        configSplit.setContinuousLayout(True)

        # ── Params panel (table + find-in-proxy button + proxy values) ───
        paramPanel = JPanel(BorderLayout(0, 4))
        paramPanel.setBorder(BorderFactory.createTitledBorder("Parameters"))

        paramCols = ["Name", "In", "Type", "Required", "Value"]
        self._paramModel = DefaultTableModel(paramCols, 0)
        self._paramTable = _EditableTable(self._paramModel, [4])
        self._paramTable.getColumnModel().getColumn(0).setPreferredWidth(140)
        self._paramTable.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(2).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(3).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(4).setPreferredWidth(250)
        paramPanel.add(JScrollPane(self._paramTable), BorderLayout.CENTER)

        # Find-in-proxy button row
        proxyBtnRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        self._findProxyBtn = JButton("Find Values in Proxy History",
                                     actionPerformed=self._onFindInProxy)
        proxyBtnRow.add(self._findProxyBtn)
        self._useValueBtn = JButton("Use Selected Value",
                                    actionPerformed=self._onUseProxyValue)
        self._useValueBtn.setEnabled(False)
        proxyBtnRow.add(self._useValueBtn)
        paramPanel.add(proxyBtnRow, BorderLayout.SOUTH)

        # Proxy values sub-split (param table top, proxy grid bottom)
        paramProxySplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        paramProxySplit.setResizeWeight(0.45)
        paramProxySplit.setDividerSize(8)
        paramProxySplit.setContinuousLayout(True)
        paramPanel.setMinimumSize(Dimension(200, 80))
        paramProxySplit.setTopComponent(paramPanel)

        proxyValCols = ["Param", "Value", "Source URL", "Found In"]
        self._proxyValModel = DefaultTableModel(proxyValCols, 0)
        self._proxyValTable = _EditableTable(self._proxyValModel, [])
        self._proxyValTable.getColumnModel().getColumn(0).setPreferredWidth(100)
        self._proxyValTable.getColumnModel().getColumn(1).setPreferredWidth(200)
        self._proxyValTable.getColumnModel().getColumn(2).setPreferredWidth(250)
        self._proxyValTable.getColumnModel().getColumn(3).setPreferredWidth(50)
        self._proxyValTable.addMouseListener(_ProxyValClickListener(self))
        proxyValScroll = JScrollPane(self._proxyValTable)
        proxyValScroll.setBorder(BorderFactory.createTitledBorder(
            "Found in Proxy (click a row, then 'Use Selected Value')"))
        proxyValScroll.setMinimumSize(Dimension(200, 60))
        paramProxySplit.setBottomComponent(proxyValScroll)

        paramProxySplit.setMinimumSize(Dimension(200, 150))
        configSplit.setLeftComponent(paramProxySplit)

        # ── JWT panel ────────────────────────────────────────────────────
        jwtPanel = JPanel(BorderLayout(0, 4))
        jwtPanel.setBorder(BorderFactory.createTitledBorder("JWT Tokens"))

        jwtCols = ["Name", "Token"]
        self._jwtModel = DefaultTableModel(jwtCols, 0)
        self._jwtTable = _EditableTable(self._jwtModel, [0, 1])
        self._jwtTable.getColumnModel().getColumn(0).setPreferredWidth(100)
        self._jwtTable.getColumnModel().getColumn(1).setPreferredWidth(300)
        jwtPanel.add(JScrollPane(self._jwtTable), BorderLayout.CENTER)

        jwtBtnRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        jwtBtnRow.add(JButton("Add JWT", actionPerformed=self._onAddJWT))
        jwtBtnRow.add(JButton("Remove Selected", actionPerformed=self._onRemoveJWT))
        jwtBtnRow.add(JButton("Clear All", actionPerformed=lambda e: self._jwtModel.setRowCount(0)))
        jwtPanel.add(jwtBtnRow, BorderLayout.SOUTH)

        configSplit.setRightComponent(jwtPanel)
        jwtPanel.setMinimumSize(Dimension(200, 150))
        centerPanel.add(configSplit, BorderLayout.CENTER)

        # Send button row
        sendRow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        self._autoScanBtn = JButton(" Auto Scan All Endpoints ",
                                     actionPerformed=self._onAutoScan)
        self._autoScanBtn.setToolTipText(
            "Scan all endpoints: auto-fill params from proxy, send with each JWT")
        sendRow.add(self._autoScanBtn)
        self._sendBtn = JButton("   Send Requests   ", actionPerformed=self._onSend)
        self._sendBtn.setFont(self._sendBtn.getFont().deriveFont(Font.BOLD, 13.0))
        sendRow.add(self._sendBtn)
        centerPanel.add(sendRow, BorderLayout.SOUTH)

        configTab.add(centerPanel, BorderLayout.CENTER)

        self._topTabs.addTab("Configuration", configTab)

        # ══════════════════════════════════════════════════════════════════
        #  TAB 2: REQUESTS
        # ══════════════════════════════════════════════════════════════════
        requestsTab = JPanel(BorderLayout(0, 4))
        requestsTab.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # ── Sub-tabs: Manual + Auto Scan endpoint tabs ───────────────────
        self._resultsTabbedPane = JTabbedPane()

        # ── Manual results sub-tab (just the results grid) ───────────────
        resultCols = ["#", "Identity", "Status", "Size (bytes)", "Time (ms)"]
        self._resultModel = DefaultTableModel(resultCols, 0)
        self._resultTable = _EditableTable(self._resultModel, [])
        self._resultTable.getColumnModel().getColumn(0).setPreferredWidth(30)
        self._resultTable.getColumnModel().getColumn(1).setPreferredWidth(200)
        self._resultTable.getColumnModel().getColumn(2).setPreferredWidth(60)
        self._resultTable.getColumnModel().getColumn(3).setPreferredWidth(80)
        self._resultTable.getColumnModel().getColumn(4).setPreferredWidth(70)
        self._resultTable.getColumnModel().getColumn(2).setCellRenderer(_StatusRenderer())
        self._resultTable.addMouseListener(_ResultClickListener(self))
        resultScroll = JScrollPane(self._resultTable)
        self._resultsTabbedPane.addTab("Manual", resultScroll)

        # ── Shared Burp message editors (below the sub-tabs) ─────────────
        self._requestEditor = self._callbacks.createMessageEditor(self, False)
        self._responseEditor = self._callbacks.createMessageEditor(self, False)

        reqRespSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        reqRespSplit.setResizeWeight(0.50)
        reqRespSplit.setDividerSize(8)
        reqRespSplit.setContinuousLayout(True)

        reqPanel = JPanel(BorderLayout())
        reqPanel.setBorder(BorderFactory.createTitledBorder("Request Sent"))
        reqPanel.add(self._requestEditor.getComponent(), BorderLayout.CENTER)
        reqPanel.setMinimumSize(Dimension(200, 100))
        reqRespSplit.setLeftComponent(reqPanel)

        respPanel = JPanel(BorderLayout())
        respPanel.setBorder(BorderFactory.createTitledBorder("Response"))
        respPanel.add(self._responseEditor.getComponent(), BorderLayout.CENTER)
        respPanel.setMinimumSize(Dimension(200, 100))
        reqRespSplit.setRightComponent(respPanel)

        # ── Vertical split: sub-tabs on top, editors on bottom ───────────
        requestsSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        requestsSplit.setResizeWeight(0.35)
        requestsSplit.setDividerSize(8)
        requestsSplit.setContinuousLayout(True)
        self._resultsTabbedPane.setMinimumSize(Dimension(200, 80))
        reqRespSplit.setMinimumSize(Dimension(200, 100))
        requestsSplit.setTopComponent(self._resultsTabbedPane)
        requestsSplit.setBottomComponent(reqRespSplit)

        requestsTab.add(requestsSplit, BorderLayout.CENTER)

        self._topTabs.addTab("Requests", requestsTab)

        # ══════════════════════════════════════════════════════════════════

        self._mainPanel.add(self._topTabs, BorderLayout.CENTER)

        # ── Status bar ───────────────────────────────────────────────────
        self._statusLabel = JLabel("Ready — load a Swagger JSON to begin.")
        self._statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 4, 2, 4))
        self._mainPanel.add(self._statusLabel, BorderLayout.SOUTH)

        self._callbacks.addSuiteTab(self)

    # ── JSON repair helper ─────────────────────────────────────────────────

    def _tryRepairJson(self, raw):
        """Try to fix malformed JSON: truncated files or concatenated objects."""
        raw = raw.rstrip()

        # ── Case 1: Concatenated JSON objects ────────────────────────────
        # Try parsing the first object; if there's leftover, parse more and merge
        try:
            decoder = json.JSONDecoder()
            objects = []
            pos = 0
            while pos < len(raw):
                chunk = raw[pos:].lstrip()
                if not chunk:
                    break
                obj, end = decoder.raw_decode(chunk)
                objects.append(obj)
                pos += len(raw[pos:]) - len(chunk) + end

            if len(objects) > 1:
                # Merge: use first as base, merge paths from the rest
                merged = objects[0]
                for extra in objects[1:]:
                    for p, methods in extra.get("paths", {}).items():
                        if p not in merged.setdefault("paths", {}):
                            merged["paths"][p] = methods
                        else:
                            merged["paths"][p].update(methods)
                    # Merge component schemas/definitions
                    for section in ("components", "definitions"):
                        if section in extra:
                            base_sec = merged.setdefault(section, {})
                            for k, v in extra[section].items():
                                if k not in base_sec:
                                    base_sec[k] = v
                                elif isinstance(base_sec[k], dict) and isinstance(v, dict):
                                    for sk, sv in v.items():
                                        if sk not in base_sec[k]:
                                            base_sec[k][sk] = sv
                return merged

            if len(objects) == 1:
                return objects[0]  # single valid object
        except (json.JSONDecodeError, ValueError):
            pass

        # ── Case 2: Truncated JSON (missing closing braces/brackets) ─────
        stack = []
        in_string = False
        escape = False
        for ch in raw:
            if escape:
                escape = False
                continue
            if ch == '\\':
                if in_string:
                    escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in ('{', '['):
                stack.append('}' if ch == '{' else ']')
            elif ch in ('}', ']'):
                if stack and stack[-1] == ch:
                    stack.pop()

        if not stack:
            return None  # balanced already — error is something else

        suffix = ''.join(reversed(stack))
        try:
            return json.loads(raw + suffix)
        except Exception:
            return None

    # ── Event handlers ─────────────────────────────────────────────────────

    def _onLoadSwagger(self, event):
        chooser = JFileChooser()
        chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
        if chooser.showOpenDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            raw = _read_file(path)
            self._spec = json.loads(raw)
        except ValueError:
            # Attempt to repair truncated JSON (missing closing braces/brackets)
            repaired = self._tryRepairJson(raw)
            if repaired is not None:
                self._spec = repaired
                total_paths = len(repaired.get("paths", {}))
                JOptionPane.showMessageDialog(self._mainPanel,
                    "JSON required auto-repair (concatenated or truncated file).\n"
                    "Loaded successfully with %d paths." % total_paths,
                    "Warning — Auto-repaired",
                    JOptionPane.WARNING_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Failed to parse JSON and auto-repair failed.\n"
                    "Check the file for syntax errors.", "Error",
                    JOptionPane.ERROR_MESSAGE)
                return
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Failed to parse JSON:\n%s" % str(e), "Error",
                JOptionPane.ERROR_MESSAGE)
            return

        self._filePathField.setText(path)
        self._endpoints = _build_endpoints(self._spec)

        # Derive a default base URL from the spec
        if "host" in self._spec:
            scheme = "https"
            schemes = self._spec.get("schemes", [])
            if schemes:
                scheme = schemes[0]
            self._baseUrlField.setText("%s://%s" % (scheme, self._spec["host"]))
        elif "servers" in self._spec and self._spec["servers"]:
            url = self._spec["servers"][0].get("url", "")
            if url.startswith("http"):
                self._baseUrlField.setText(url.rstrip("/"))

        self._endpointCombo.removeAllItems()
        for label, _, _, _ in self._endpoints:
            self._endpointCombo.addItem(label)

        self._statusLabel.setText("Loaded %d endpoints from %s" % (len(self._endpoints), path))

    def _onEndpointChanged(self):
        idx = self._endpointCombo.getSelectedIndex()
        if idx < 0 or idx >= len(self._endpoints):
            return
        _, _, _, params = self._endpoints[idx]
        self._paramModel.setRowCount(0)
        self._proxyValModel.setRowCount(0)
        self._useValueBtn.setEnabled(False)
        for p in params:
            self._paramModel.addRow([
                p["name"],
                p["in"],
                p["type"],
                str(p["required"]),
                str(p["default"]) if p["default"] is not None else "",
            ])

    def _onAddJWT(self, event):
        name = JOptionPane.showInputDialog(self._mainPanel,
            "Enter a name for this JWT (e.g. admin, user1, guest):",
            "JWT Name", JOptionPane.PLAIN_MESSAGE)
        if name is None:
            return
        name = name.strip() if name else "JWT-%d" % (self._jwtModel.getRowCount() + 1)
        if not name:
            name = "JWT-%d" % (self._jwtModel.getRowCount() + 1)

        jwt = JOptionPane.showInputDialog(self._mainPanel,
            "Paste the JWT token for '%s':" % name,
            "Add JWT", JOptionPane.PLAIN_MESSAGE)
        if jwt and jwt.strip():
            self._jwtModel.addRow([name, jwt.strip()])

    def _onRemoveJWT(self, event):
        row = self._jwtTable.getSelectedRow()
        if row >= 0:
            self._jwtModel.removeRow(row)
        else:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select a JWT row to remove.", "Info",
                JOptionPane.INFORMATION_MESSAGE)

    def _onSend(self, event):
        idx = self._endpointCombo.getSelectedIndex()
        if idx < 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an endpoint first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        # Stop editing so any in-progress cell value is committed
        if self._jwtTable.isEditing():
            self._jwtTable.getCellEditor().stopCellEditing()

        # Collect (name, token) pairs from JWT table
        jwt_pairs = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "").strip()
            token = str(self._jwtModel.getValueAt(r, 1) or "").strip()
            if token:
                if not name:
                    name = "JWT-%d" % (r + 1)
                jwt_pairs.append((name, token))

        if not jwt_pairs:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one JWT token.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        # Stop editing so any in-progress cell value is committed
        if self._paramTable.isEditing():
            self._paramTable.getCellEditor().stopCellEditing()

        _, method, path_template, _ = self._endpoints[idx]
        base = self._baseUrlField.getText().strip().rstrip("/")

        # Gather params from table
        params = []
        for r in range(self._paramModel.getRowCount()):
            params.append({
                "name": self._paramModel.getValueAt(r, 0),
                "in": self._paramModel.getValueAt(r, 1),
                "value": self._paramModel.getValueAt(r, 4) or "",
            })

        self._resultModel.setRowCount(0)
        self._responses = []
        self._requests = []
        self._raw_requests = []
        self._raw_responses = []
        self._http_services = []
        self._currentRow = -1
        self._requestEditor.setMessage([], True)
        self._responseEditor.setMessage([], False)
        self._sendBtn.setEnabled(False)
        self._statusLabel.setText("Sending %d request(s) (1 unauthenticated + %d with JWT)…" % (len(jwt_pairs) + 1, len(jwt_pairs)))

        # Switch to Requests tab > Manual sub-tab
        self._topTabs.setSelectedIndex(1)
        self._resultsTabbedPane.setSelectedIndex(0)

        # Run requests in background thread (Java Thread for Jython reliability)
        runner = _RequestRunner(self, base, method, path_template, params, jwt_pairs,
                                self._userAgentField.getText().strip())
        JThread(runner).start()

    def _appendResult(self, row_num, jwt_prefix, status, size, elapsed,
                      resp_body, req_text="", raw_req=None, raw_resp=None, http_service=None):
        """Called from background thread via invokeLater."""
        self._resultModel.addRow([
            str(row_num), jwt_prefix, str(status), str(size), str(elapsed)
        ])
        self._responses.append(resp_body)
        self._requests.append(req_text)
        self._raw_requests.append(raw_req)
        self._raw_responses.append(raw_resp)
        self._http_services.append(http_service)

    def _onResultClick(self, row):
        if 0 <= row < len(self._responses):
            self._currentRow = row

            # Show request in Burp editor
            try:
                raw_req = self._raw_requests[row] if row < len(self._raw_requests) else None
                if raw_req:
                    self._requestEditor.setMessage(raw_req, True)
                else:
                    self._requestEditor.setMessage([], True)
            except Exception:
                self._requestEditor.setMessage([], True)

            # Show response in Burp editor
            try:
                raw_resp = self._raw_responses[row] if row < len(self._raw_responses) else None
                if raw_resp:
                    self._responseEditor.setMessage(raw_resp, False)
                else:
                    self._responseEditor.setMessage([], False)
            except Exception:
                self._responseEditor.setMessage([], False)

    # ── Proxy history search ───────────────────────────────────────────────

    def _onFindInProxy(self, event):
        """Search Burp Proxy history for values matching current parameter names."""
        if self._paramModel.getRowCount() == 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "No parameters to search for. Select an endpoint first.",
                "Warning", JOptionPane.WARNING_MESSAGE)
            return

        # Collect parameter names we're looking for
        param_names = set()
        for r in range(self._paramModel.getRowCount()):
            name = str(self._paramModel.getValueAt(r, 0)).strip()
            if name:
                param_names.add(name)

        if not param_names:
            return

        self._proxyValModel.setRowCount(0)
        self._useValueBtn.setEnabled(False)
        self._findProxyBtn.setEnabled(False)
        self._statusLabel.setText("Scanning proxy history for parameter values...")

        # Run in background to avoid freezing UI
        searcher = _ProxySearchRunner(self, param_names)
        JThread(searcher).start()

    def _onProxySearchDone(self, results):
        """Called on EDT when proxy search completes. results = list of (param, value, url, method)."""
        self._proxyValModel.setRowCount(0)
        for param, value, url, method in results:
            self._proxyValModel.addRow([param, value, url, method])
        self._findProxyBtn.setEnabled(True)
        if results:
            self._useValueBtn.setEnabled(True)
            self._statusLabel.setText(
                "Found %d value(s) across proxy history." % len(results))
        else:
            self._statusLabel.setText("No matching parameter values found in proxy history.")

    def _onUseProxyValue(self, event):
        """Copy the selected proxy-found value into the parameter table."""
        row = self._proxyValTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select a row in the proxy values grid first.",
                "Info", JOptionPane.INFORMATION_MESSAGE)
            return

        param_name = str(self._proxyValModel.getValueAt(row, 0))
        value = str(self._proxyValModel.getValueAt(row, 1))

        # Find matching parameter in param table and set its value
        matched = False
        for r in range(self._paramModel.getRowCount()):
            if str(self._paramModel.getValueAt(r, 0)) == param_name:
                self._paramModel.setValueAt(value, r, 4)
                matched = True
                break

        if matched:
            self._statusLabel.setText(
                "Set '%s' = '%s'" % (param_name, value[:60] + "..." if len(value) > 60 else value))
        else:
            self._statusLabel.setText(
                "Parameter '%s' not found in current endpoint." % param_name)

    # ── Auto Scan ──────────────────────────────────────────────────────────

    def _onAutoScan(self, event):
        """Scan every endpoint: auto-fill params from proxy, send all JWTs."""
        if not self._endpoints:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Load a Swagger file first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        # Stop editing so any in-progress cell value is committed
        if self._jwtTable.isEditing():
            self._jwtTable.getCellEditor().stopCellEditing()

        # Collect JWTs
        jwt_pairs = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "").strip()
            token = str(self._jwtModel.getValueAt(r, 1) or "").strip()
            if token:
                if not name:
                    name = "JWT-%d" % (r + 1)
                jwt_pairs.append((name, token))

        if not jwt_pairs:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one JWT token.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        confirm = JOptionPane.showConfirmDialog(self._mainPanel,
            "This will scan all %d endpoints with %d JWT(s) + unauthenticated.\n"
            "Total requests: %d\n\nContinue?" % (
                len(self._endpoints), len(jwt_pairs),
                len(self._endpoints) * (len(jwt_pairs) + 1)),
            "Confirm Auto Scan", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return

        base = self._baseUrlField.getText().strip().rstrip("/")

        # Remove previous auto-scan tabs (keep tab 0 = Manual)
        while self._resultsTabbedPane.getTabCount() > 1:
            self._resultsTabbedPane.removeTabAt(self._resultsTabbedPane.getTabCount() - 1)
        self._autoScanTabs = []

        # Create one tab per endpoint
        for idx, (label, method, path_template, params) in enumerate(self._endpoints):
            tab_data = self._createAutoScanTab(label, method)
            self._autoScanTabs.append(tab_data)

        self._autoScanBtn.setEnabled(False)
        self._sendBtn.setEnabled(False)
        self._statusLabel.setText("Auto Scan: starting %d endpoints..." % len(self._endpoints))

        # Switch to Requests tab > first auto-scan sub-tab
        self._topTabs.setSelectedIndex(1)
        if self._resultsTabbedPane.getTabCount() > 1:
            self._resultsTabbedPane.setSelectedIndex(1)

        runner = _AutoScanRunner(self, base, self._endpoints, jwt_pairs,
                                 self._userAgentField.getText().strip())
        JThread(runner).start()

    def _createAutoScanTab(self, label, method="GET"):
        """Create a results tab for one endpoint and return its data dict."""
        is_mutating = method in ("POST", "PUT", "PATCH", "DELETE")

        resultCols = ["#", "Identity", "Status", "Size (bytes)", "Time (ms)"]
        model = DefaultTableModel(resultCols, 0)
        table = _EditableTable(model, [])
        table.getColumnModel().getColumn(0).setPreferredWidth(30)
        table.getColumnModel().getColumn(1).setPreferredWidth(200)
        table.getColumnModel().getColumn(2).setPreferredWidth(60)
        table.getColumnModel().getColumn(3).setPreferredWidth(80)
        table.getColumnModel().getColumn(4).setPreferredWidth(70)
        table.getColumnModel().getColumn(2).setCellRenderer(_StatusRenderer())

        tab_data = {
            "model": model,
            "table": table,
            "responses": [],
            "requests": [],
            "raw_requests": [],
            "raw_responses": [],
            "http_services": [],
            "pending": is_mutating,
            "method": method,
            "params": None,       # filled by auto scan runner
            "path_template": None, # filled by auto scan runner
        }

        # Click listener that updates the shared editors below
        table.addMouseListener(_AutoTabClickListener(self, tab_data))

        scrollPane = JScrollPane(table)

        if is_mutating:
            # Wrap in a panel with a confirm banner + preview + results
            tabPanel = JPanel(BorderLayout(0, 4))

            # ── Confirm banner ───────────────────────────────────────────
            bannerPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
            bannerPanel.setBorder(BorderFactory.createLineBorder(Color(200, 120, 0), 2))
            bannerPanel.setBackground(Color(255, 245, 220))

            warnLabel = JLabel("  %s request — review preview below, then confirm  " % method)
            warnLabel.setFont(warnLabel.getFont().deriveFont(Font.BOLD))
            warnLabel.setForeground(Color(180, 90, 0))
            bannerPanel.add(warnLabel)

            confirmBtn = JButton("Confirm & Send")
            confirmBtn.setFont(confirmBtn.getFont().deriveFont(Font.BOLD))
            confirmBtn.addActionListener(
                lambda e, td=tab_data, bp=bannerPanel: self._onConfirmSend(td, bp))
            bannerPanel.add(confirmBtn)

            skipBtn = JButton("Skip")
            skipBtn.addActionListener(
                lambda e, bp=bannerPanel: self._onSkipEndpoint(bp))
            bannerPanel.add(skipBtn)

            tab_data["banner"] = bannerPanel
            tab_data["confirmBtn"] = confirmBtn

            # ── Preview area ─────────────────────────────────────────────
            previewArea = JTextArea(6, 60)
            previewArea.setEditable(False)
            previewArea.setFont(Font("Monospaced", Font.PLAIN, 12))
            previewArea.setLineWrap(True)
            previewArea.setWrapStyleWord(True)
            previewArea.setText("  Waiting for auto-scan to fill parameters...")
            previewScroll = JScrollPane(previewArea)
            previewScroll.setBorder(BorderFactory.createTitledBorder(
                "Request Preview (what will be sent)"))
            previewScroll.setMinimumSize(Dimension(200, 80))

            tab_data["previewArea"] = previewArea

            # ── Layout: banner on top, preview + results in a split ──────
            previewResultSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            previewResultSplit.setResizeWeight(0.4)
            previewResultSplit.setDividerSize(8)
            previewResultSplit.setContinuousLayout(True)
            previewScroll.setMinimumSize(Dimension(100, 40))
            scrollPane.setMinimumSize(Dimension(100, 40))
            previewResultSplit.setTopComponent(previewScroll)
            previewResultSplit.setBottomComponent(scrollPane)
            previewResultSplit.setMinimumSize(Dimension(100, 100))

            # Use a nested split so banner is also resizable
            outerSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            outerSplit.setResizeWeight(0.0)
            outerSplit.setDividerSize(4)
            outerSplit.setContinuousLayout(True)
            bannerPanel.setMinimumSize(Dimension(100, 30))
            bannerPanel.setPreferredSize(Dimension(800, 40))
            outerSplit.setTopComponent(bannerPanel)
            outerSplit.setBottomComponent(previewResultSplit)

            tabContent = outerSplit
        else:
            tabContent = scrollPane

        # Truncate label for tab title
        short_label = label if len(label) <= 35 else label[:32] + "..."
        self._resultsTabbedPane.addTab(short_label, tabContent)
        idx = self._resultsTabbedPane.getTabCount() - 1
        self._resultsTabbedPane.setToolTipTextAt(idx, label)

        return tab_data

    def _onConfirmSend(self, tab_data, bannerPanel):
        """User confirmed sending for a mutating endpoint."""
        tab_data["pending"] = False

        # Disable the confirm button and update banner
        tab_data["confirmBtn"].setEnabled(False)
        bannerPanel.setBackground(Color(220, 245, 220))
        bannerPanel.setBorder(BorderFactory.createLineBorder(Color(80, 160, 80), 2))
        for comp in bannerPanel.getComponents():
            if isinstance(comp, JLabel):
                comp.setText("  Sending...  ")
                comp.setForeground(Color(60, 130, 60))

        # Collect current JWTs
        jwt_pairs = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "").strip()
            token = str(self._jwtModel.getValueAt(r, 1) or "").strip()
            if token:
                if not name:
                    name = "JWT-%d" % (r + 1)
                jwt_pairs.append((name, token))

        base = self._baseUrlField.getText().strip().rstrip("/")

        # Send in background
        runner = _PendingEndpointRunner(
            self, tab_data, base, jwt_pairs, bannerPanel,
            self._userAgentField.getText().strip())
        JThread(runner).start()

    def _onSkipEndpoint(self, bannerPanel):
        """User chose to skip this mutating endpoint."""
        bannerPanel.setBackground(Color(230, 230, 230))
        bannerPanel.setBorder(BorderFactory.createLineBorder(Color(160, 160, 160), 1))
        for comp in bannerPanel.getComponents():
            if isinstance(comp, JLabel):
                comp.setText("  Skipped  ")
                comp.setForeground(Color(120, 120, 120))
            elif isinstance(comp, JButton):
                comp.setEnabled(False)

    def _onAutoTabClick(self, tab_data, row):
        """Handle click on a row in an auto-scan tab — update shared editors."""
        if 0 <= row < len(tab_data["raw_requests"]):
            # Point IMessageEditorController to this tab's data
            self._raw_requests = tab_data["raw_requests"]
            self._raw_responses = tab_data["raw_responses"]
            self._http_services = tab_data["http_services"]
            self._currentRow = row

            try:
                raw_req = tab_data["raw_requests"][row]
                if raw_req:
                    self._requestEditor.setMessage(raw_req, True)
                else:
                    self._requestEditor.setMessage([], True)
            except Exception:
                self._requestEditor.setMessage([], True)

            try:
                raw_resp = tab_data["raw_responses"][row]
                if raw_resp:
                    self._responseEditor.setMessage(raw_resp, False)
                else:
                    self._responseEditor.setMessage([], False)
            except Exception:
                self._responseEditor.setMessage([], False)

    # ── State save / load ──────────────────────────────────────────────────

    def _collectState(self):
        """Gather every piece of UI state into a serialisable dict."""
        # Stop any active cell editing so the value is committed
        if self._paramTable.isEditing():
            self._paramTable.getCellEditor().stopCellEditing()
        if self._jwtTable.isEditing():
            self._jwtTable.getCellEditor().stopCellEditing()

        state = {}
        state["swagger_path"] = self._filePathField.getText()
        state["base_url"] = self._baseUrlField.getText()
        state["user_agent"] = self._userAgentField.getText()
        state["selected_endpoint"] = self._endpointCombo.getSelectedIndex()

        # Parameter values keyed by name (so they survive endpoint reloads)
        param_values = {}
        for r in range(self._paramModel.getRowCount()):
            name = str(self._paramModel.getValueAt(r, 0))
            val = str(self._paramModel.getValueAt(r, 4) or "")
            if val:
                param_values[name] = val
        state["param_values"] = param_values

        # Named JWTs
        jwt_pairs = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "")
            token = str(self._jwtModel.getValueAt(r, 1) or "")
            if token:
                jwt_pairs.append({"name": name, "token": token})
        state["jwt_pairs"] = jwt_pairs

        return state

    def _applyState(self, state):
        """Restore UI from a state dict. Reloads the swagger if the file exists."""
        # 1. Reload swagger if path is present
        swagger_path = state.get("swagger_path", "")
        if swagger_path:
            try:
                raw = _read_file(swagger_path)
                self._spec = json.loads(raw)
                self._filePathField.setText(swagger_path)
                self._endpoints = _build_endpoints(self._spec)

                # Temporarily disconnect the combo listener so it doesn't
                # fire _onEndpointChanged for every addItem
                listeners = self._endpointCombo.getActionListeners()
                for li in listeners:
                    self._endpointCombo.removeActionListener(li)

                self._endpointCombo.removeAllItems()
                for label, _, _, _ in self._endpoints:
                    self._endpointCombo.addItem(label)

                # Re-attach listeners
                for li in listeners:
                    self._endpointCombo.addActionListener(li)
            except Exception as e:
                self._statusLabel.setText(
                    "Warning: could not reload swagger from '%s': %s" % (swagger_path, str(e)))

        # 2. Base URL
        base_url = state.get("base_url", "")
        if base_url:
            self._baseUrlField.setText(base_url)

        # 2b. User-Agent
        user_agent = state.get("user_agent", "")
        if user_agent:
            self._userAgentField.setText(user_agent)

        # 3. Select endpoint (triggers _onEndpointChanged which populates params)
        ep_idx = state.get("selected_endpoint", -1)
        if 0 <= ep_idx < self._endpointCombo.getItemCount():
            self._endpointCombo.setSelectedIndex(ep_idx)

        # 4. Restore parameter values by name
        param_values = state.get("param_values", {})
        for r in range(self._paramModel.getRowCount()):
            name = str(self._paramModel.getValueAt(r, 0))
            if name in param_values:
                self._paramModel.setValueAt(param_values[name], r, 4)

        # 5. Named JWTs
        self._jwtModel.setRowCount(0)
        jwt_pairs = state.get("jwt_pairs", [])
        for pair in jwt_pairs:
            name = pair.get("name", "")
            token = pair.get("token", "")
            if token:
                self._jwtModel.addRow([name, token])

        # Backward compat: old state files with plain "jwts" list
        if not jwt_pairs:
            old_jwts = state.get("jwts", [])
            for i, token in enumerate(old_jwts):
                self._jwtModel.addRow(["JWT-%d" % (i + 1), token])

    def _onSaveState(self, event):
        """Save current state to a JSON file chosen by the user."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Extension State")
        chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
        chooser.setSelectedFile(File("swagger-jwt-state.json"))
        if chooser.showSaveDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.endswith(".json"):
            path += ".json"

        try:
            state = self._collectState()
            with open(path, "w") as f:
                f.write(json.dumps(state, indent=2))
            self._statusLabel.setText("State saved to %s" % path)
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Failed to save state:\n%s" % str(e), "Error",
                JOptionPane.ERROR_MESSAGE)

    def _onLoadState(self, event):
        """Load state from a JSON file chosen by the user."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Extension State")
        chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
        if chooser.showOpenDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            raw = _read_file(path)
            state = json.loads(raw)
            self._applyState(state)
            self._statusLabel.setText("State loaded from %s" % path)
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Failed to load state:\n%s" % str(e), "Error",
                JOptionPane.ERROR_MESSAGE)


# ── Mouse listener for proxy values table ──────────────────────────────────

class _ProxyValClickListener(MouseAdapter):
    def __init__(self, extender):
        self._ext = extender

    def mouseClicked(self, event):
        row = self._ext._proxyValTable.getSelectedRow()
        if row >= 0:
            self._ext._useValueBtn.setEnabled(True)
            # Double-click = immediate use
            if event.getClickCount() == 2:
                self._ext._onUseProxyValue(event)


# ── Mouse listener for result table ────────────────────────────────────────

class _ResultClickListener(MouseAdapter):
    def __init__(self, extender):
        self._ext = extender

    def mouseClicked(self, event):
        row = self._ext._resultTable.getSelectedRow()
        if row >= 0:
            self._ext._onResultClick(row)


# ── Proxy history searcher ─────────────────────────────────────────────────

class _ProxySearchRunner(Runnable):
    """Scans Burp Proxy history for parameter values matching given names
    in both requests and responses."""

    def __init__(self, extender, param_names):
        self._ext = extender
        self._param_names = param_names  # set of strings

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[ProxySearch] %s" % msg)
        except Exception:
            pass

    def run(self):
        results = []
        seen = set()  # (param, value, source_type) dedup

        try:
            history = self._ext._callbacks.getProxyHistory()
            self._log("Scanning %d proxy history items (requests + responses)..." % len(history))

            for item in history:
                try:
                    helpers = self._ext._helpers
                    req_bytes = item.getRequest()
                    if req_bytes is None:
                        continue

                    req_info = helpers.analyzeRequest(item.getHttpService(), req_bytes)
                    url = str(req_info.getUrl())
                    method = str(req_info.getMethod())
                    display_url = url if len(url) <= 80 else url[:77] + "..."

                    # ── 1. Request: IParameter list from Burp ────────────
                    for param in req_info.getParameters():
                        pname = str(param.getName())
                        pval = str(param.getValue())
                        if pname in self._param_names and pval:
                            key = (pname, pval, "req")
                            if key not in seen:
                                seen.add(key)
                                results.append((pname, pval, display_url,
                                                "%s request" % method))

                    # ── 2. Request: JSON body fields ─────────────────────
                    req_body_offset = req_info.getBodyOffset()
                    if req_body_offset < len(req_bytes):
                        req_body_str = helpers.bytesToString(req_bytes[req_body_offset:])
                        if req_body_str and req_body_str.strip().startswith("{"):
                            try:
                                req_json = json.loads(req_body_str)
                                self._extract_json_params(
                                    req_json, display_url,
                                    "%s request body" % method,
                                    results, seen)
                            except Exception:
                                pass

                    # ── 3. Response: JSON body fields ────────────────────
                    resp_bytes = item.getResponse()
                    if resp_bytes is not None:
                        resp_info = helpers.analyzeResponse(resp_bytes)
                        resp_body_offset = resp_info.getBodyOffset()
                        if resp_body_offset < len(resp_bytes):
                            resp_body_str = helpers.bytesToString(
                                resp_bytes[resp_body_offset:])
                            if resp_body_str and resp_body_str.strip():
                                first_char = resp_body_str.strip()[0]
                                if first_char in ("{", "["):
                                    try:
                                        resp_json = json.loads(resp_body_str)
                                        self._extract_json_params(
                                            resp_json, display_url,
                                            "%s response" % method,
                                            results, seen)
                                    except Exception:
                                        pass

                except Exception:
                    continue

            self._log("Search done: %d unique values found." % len(results))

        except Exception as e:
            self._log("Error scanning proxy: %s\n%s" % (
                str(e), traceback.format_exc()))

        # Sort: group by param name
        results.sort(key=lambda x: x[0])

        class _Done(Runnable):
            def __init__(s):
                s.res = results
            def run(s):
                self._ext._onProxySearchDone(s.res)
        SwingUtilities.invokeLater(_Done())

    def _extract_json_params(self, obj, display_url, source_label, results, seen, prefix=""):
        """Recursively extract matching keys from a JSON object or array."""
        if isinstance(obj, dict):
            for key, val in obj.items():
                full_key = ("%s.%s" % (prefix, key)) if prefix else key
                # Match on the leaf key name
                if key in self._param_names and val is not None:
                    str_val = str(val)
                    if str_val:
                        dedup = (key, str_val, source_label)
                        if dedup not in seen:
                            seen.add(dedup)
                            results.append((key, str_val, display_url, source_label))
                # Recurse into nested objects/arrays
                if isinstance(val, dict):
                    self._extract_json_params(
                        val, display_url, source_label, results, seen, full_key)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            self._extract_json_params(
                                item, display_url, source_label, results, seen, full_key)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._extract_json_params(
                        item, display_url, source_label, results, seen, prefix)



# ── Mouse listener for auto-scan tab tables ────────────────────────────────

class _AutoTabClickListener(MouseAdapter):
    def __init__(self, extender, tab_data):
        self._ext = extender
        self._tab_data = tab_data

    def mouseClicked(self, event):
        row = self._tab_data["table"].getSelectedRow()
        if row >= 0:
            self._ext._onAutoTabClick(self._tab_data, row)


# ── Auto Scan runner ───────────────────────────────────────────────────────

class _AutoScanRunner(Runnable):
    """Iterates all endpoints, auto-fills params from proxy, sends requests."""

    def __init__(self, extender, base, endpoints, jwt_pairs, user_agent="SwaggerJWTTester-Burp/1.0"):
        self._ext = extender
        self._base = base
        self._endpoints = endpoints
        self._jwt_pairs = jwt_pairs
        self._user_agent = user_agent

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[AutoScan] %s" % msg)
        except Exception:
            pass

    def run(self):
        import time
        helpers = self._ext._helpers
        total_ep = len(self._endpoints)

        # ── Pre-build proxy param cache (search once, reuse for all) ─────
        self._log("Building proxy parameter cache...")
        proxy_cache = {}  # {param_name: first_value_found}
        try:
            history = self._ext._callbacks.getProxyHistory()
            for item in history:
                try:
                    req_bytes = item.getRequest()
                    if req_bytes is None:
                        continue
                    req_info = helpers.analyzeRequest(item.getHttpService(), req_bytes)

                    # Request params
                    for param in req_info.getParameters():
                        pname = str(param.getName())
                        pval = str(param.getValue())
                        if pname and pval and pname not in proxy_cache:
                            proxy_cache[pname] = pval

                    # Request JSON body
                    req_bo = req_info.getBodyOffset()
                    if req_bo < len(req_bytes):
                        body_str = helpers.bytesToString(req_bytes[req_bo:])
                        if body_str and body_str.strip().startswith("{"):
                            try:
                                self._cache_json(json.loads(body_str), proxy_cache)
                            except Exception:
                                pass

                    # Response JSON body
                    resp_bytes = item.getResponse()
                    if resp_bytes:
                        resp_info = helpers.analyzeResponse(resp_bytes)
                        resp_bo = resp_info.getBodyOffset()
                        if resp_bo < len(resp_bytes):
                            resp_str = helpers.bytesToString(resp_bytes[resp_bo:])
                            if resp_str and resp_str.strip()[:1] in ("{", "["):
                                try:
                                    self._cache_json(json.loads(resp_str), proxy_cache)
                                except Exception:
                                    pass
                except Exception:
                    continue
        except Exception as e:
            self._log("Proxy cache error: %s" % str(e))

        self._log("Proxy cache: %d param names found." % len(proxy_cache))

        # ── Process each endpoint ────────────────────────────────────────
        for ep_idx, (label, method, path_template, param_defs) in enumerate(self._endpoints):
            tab_data = self._ext._autoScanTabs[ep_idx]
            ep_num = ep_idx + 1

            class _UpdateStatus(Runnable):
                def __init__(s):
                    s.msg = "Auto Scan: [%d/%d] %s" % (ep_num, total_ep, label)
                def run(s):
                    self._ext._statusLabel.setText(s.msg)
                    # Switch to this endpoint's tab
                    tab_idx = ep_idx + 1  # +1 because tab 0 is Manual
                    if tab_idx < self._ext._resultsTabbedPane.getTabCount():
                        self._ext._resultsTabbedPane.setSelectedIndex(tab_idx)
            SwingUtilities.invokeLater(_UpdateStatus())

            self._log("[%d/%d] Processing %s" % (ep_num, total_ep, label))

            # Auto-fill params from cache
            params = []
            for p in param_defs:
                value = proxy_cache.get(p["name"], "")
                if not value and p.get("default"):
                    value = str(p["default"])
                # For required params with no value found, use the param name
                if not value and p.get("required"):
                    value = p["name"]
                params.append({
                    "name": p["name"],
                    "in": p["in"],
                    "value": value,
                })

            # Store params in tab_data for potential deferred sending
            tab_data["params"] = params
            tab_data["path_template"] = path_template

            # Skip mutating methods — user must confirm via the banner button
            if tab_data.get("pending"):
                self._log("[%d/%d] PENDING (mutating %s) — waiting for confirm" % (
                    ep_num, total_ep, method))

                # Build a preview of what would be sent
                preview = self._buildPreview(
                    method, path_template, params, self._base)

                class _SetPreview(Runnable):
                    def __init__(s):
                        s.text = preview
                        s.td = tab_data
                    def run(s):
                        pa = s.td.get("previewArea")
                        if pa:
                            pa.setText(s.text)
                            pa.setCaretPosition(0)

                SwingUtilities.invokeLater(_SetPreview())
                continue

            # ── Send unauthenticated request ─────────────────────────────
            row_num = 0
            row_num += 1
            self._sendOne(tab_data, row_num, "<No Auth>", None,
                          method, path_template, params)

            # ── Send one request per JWT ─────────────────────────────────
            for jwt_name, jwt_token in self._jwt_pairs:
                row_num += 1
                self._sendOne(tab_data, row_num, jwt_name, jwt_token,
                              method, path_template, params)

        # ── Done ─────────────────────────────────────────────────────────
        class _Done(Runnable):
            def run(s):
                self._ext._autoScanBtn.setEnabled(True)
                self._ext._sendBtn.setEnabled(True)
                self._ext._statusLabel.setText(
                    "Auto Scan complete — %d endpoints, %d requests each." % (
                        total_ep, len(self._jwt_pairs) + 1))
        SwingUtilities.invokeLater(_Done())

    def _buildPreview(self, method, path_template, params, base):
        """Build a human-readable preview of the request that will be sent."""
        lines = []

        # Construct URL with path params substituted
        path = path_template
        query_parts = []
        body_obj = {}

        for p in params:
            val = p["value"]
            if not val:
                continue
            if p["in"] == "path":
                path = path.replace("{%s}" % p["name"], val)
            elif p["in"] == "query":
                query_parts.append("%s=%s" % (p["name"], val))
            elif p["in"] == "body":
                body_obj[p["name"]] = val

        url = base + path
        if query_parts:
            url += "?" + "&".join(query_parts)

        lines.append("== REQUEST PREVIEW ==")
        lines.append("")
        lines.append("%s %s HTTP/1.1" % (method, url))
        lines.append("Host: %s" % base.split("//")[-1].split("/")[0])
        lines.append("Authorization: Bearer <each JWT will be inserted>")
        lines.append("Content-Type: application/json")
        lines.append("User-Agent: %s" % self._user_agent)
        lines.append("")

        # Parameters summary
        lines.append("== PARAMETERS ==")
        lines.append("")
        for p in params:
            src = "(from proxy)" if p["value"] and p["value"] != p["name"] else "(default/name)" if p["value"] else "(empty)"
            lines.append("  %-20s [%-5s]  = %s  %s" % (
                p["name"], p["in"],
                p["value"] if p["value"] else "<not set>",
                src))

        # Body preview for POST/PUT/PATCH
        if body_obj and method in ("POST", "PUT", "PATCH"):
            lines.append("")
            lines.append("== REQUEST BODY ==")
            lines.append("")
            try:
                lines.append(json.dumps(body_obj, indent=2))
            except Exception:
                lines.append(str(body_obj))

        # JWT list
        lines.append("")
        lines.append("== WILL SEND %d REQUEST(S) ==" % (len(self._jwt_pairs) + 1))
        lines.append("")
        lines.append("  1. <No Auth>  (no Authorization header)")
        for i, (name, _) in enumerate(self._jwt_pairs):
            lines.append("  %d. %s" % (i + 2, name))

        return "\n".join(lines)

    def _sendOne(self, tab_data, row_num, identity, jwt_token, method, path_template, params):
        """Send a single request and add the result to tab_data."""
        import time
        helpers = self._ext._helpers

        try:
            path = path_template
            query_parts = []
            body_obj = {}

            for p in params:
                val = p["value"]
                if not val:
                    continue
                if p["in"] == "path":
                    path = path.replace("{%s}" % p["name"], val)
                elif p["in"] == "query":
                    query_parts.append("%s=%s" % (
                        helpers.urlEncode(p["name"]),
                        helpers.urlEncode(val)))
                elif p["in"] == "body":
                    body_obj[p["name"]] = val

            url_path = path
            if query_parts:
                url_path += "?" + "&".join(query_parts)

            full_url_str = self._base + url_path
            url_obj = java.net.URL(full_url_str)
            host = url_obj.getHost()
            port = url_obj.getPort()
            use_https = full_url_str.startswith("https")
            if port == -1:
                port = 443 if use_https else 80

            path_for_request = url_obj.getPath()
            if url_obj.getQuery():
                path_for_request += "?" + url_obj.getQuery()
            if not path_for_request:
                path_for_request = "/"

            headers = [
                "%s %s HTTP/1.1" % (method, path_for_request),
                "Host: %s" % host,
            ]
            if jwt_token:
                headers.append("Authorization: Bearer %s" % jwt_token)
            headers += [
                "User-Agent: %s" % self._user_agent,
                "Accept: */*",
                "Connection: close",
            ]

            body_bytes = None
            if body_obj and method in ("POST", "PUT", "PATCH"):
                body_str = json.dumps(body_obj)
                body_bytes = helpers.stringToBytes(body_str)
                headers.append("Content-Type: application/json")
                headers.append("Content-Length: %d" % len(body_str))

            request = helpers.buildHttpMessage(headers, body_bytes)
            http_service = helpers.buildHttpService(host, port, use_https)

            t0 = time.time()
            response = self._ext._callbacks.makeHttpRequest(http_service, request)
            elapsed = int((time.time() - t0) * 1000)

            resp_bytes = response.getResponse()
            if resp_bytes is None:
                status = "N/A"; size = 0
                raw_resp = None
            else:
                resp_info = helpers.analyzeResponse(resp_bytes)
                status = resp_info.getStatusCode()
                size = len(resp_bytes)
                raw_resp = resp_bytes

            cur_row = row_num

            class _AddRow(Runnable):
                def __init__(s):
                    s.r = cur_row; s.id = identity; s.st = status
                    s.sz = size; s.el = elapsed
                    s.rq = request; s.rsp = raw_resp; s.svc = http_service
                def run(s):
                    tab_data["model"].addRow([
                        str(s.r), s.id, str(s.st), str(s.sz), str(s.el)])
                    tab_data["raw_requests"].append(s.rq)
                    tab_data["raw_responses"].append(s.rsp)
                    tab_data["http_services"].append(s.svc)

            SwingUtilities.invokeLater(_AddRow())

        except Exception as e:
            self._log("Error [%s]: %s" % (identity, str(e)))
            err_msg = str(e)
            cur_row = row_num

            class _AddErr(Runnable):
                def __init__(s):
                    s.r = cur_row; s.id = identity; s.err = err_msg
                def run(s):
                    tab_data["model"].addRow([
                        str(s.r), s.id, "ERR", "0", "0"])
                    tab_data["raw_requests"].append(None)
                    tab_data["raw_responses"].append(None)
                    tab_data["http_services"].append(None)

            SwingUtilities.invokeLater(_AddErr())

    def _cache_json(self, obj, cache):
        """Recursively extract key-value pairs from JSON into cache."""
        if isinstance(obj, dict):
            for key, val in obj.items():
                if val is not None and key not in cache:
                    if isinstance(val, (str, int, float, bool)):
                        str_val = str(val)
                        if str_val:
                            cache[key] = str_val
                if isinstance(val, dict):
                    self._cache_json(val, cache)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            self._cache_json(item, cache)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._cache_json(item, cache)


# ── Pending endpoint runner (for confirmed mutating methods) ───────────────

class _PendingEndpointRunner(Runnable):
    """Sends requests for a single endpoint after user confirmation."""

    def __init__(self, extender, tab_data, base, jwt_pairs, banner_panel, user_agent="SwaggerJWTTester-Burp/1.0"):
        self._ext = extender
        self._tab = tab_data
        self._base = base
        self._jwt_pairs = jwt_pairs
        self._banner = banner_panel
        self._user_agent = user_agent

    def run(self):
        import time
        helpers = self._ext._helpers
        method = self._tab["method"]
        path_template = self._tab["path_template"]
        params = self._tab["params"]

        row_num = 0

        # Unauthenticated
        row_num += 1
        self._fire(helpers, row_num, "<No Auth>", None,
                   method, path_template, params)

        # Each JWT
        for jwt_name, jwt_token in self._jwt_pairs:
            row_num += 1
            self._fire(helpers, row_num, jwt_name, jwt_token,
                       method, path_template, params)

        # Update banner to done
        class _Done(Runnable):
            def run(s):
                for comp in self._banner.getComponents():
                    if isinstance(comp, JLabel):
                        comp.setText("  Done — %d requests sent  " % row_num)
                self._ext._statusLabel.setText(
                    "Confirmed %s %s — %d request(s) sent." % (
                        method, path_template, row_num))
        SwingUtilities.invokeLater(_Done())

    def _fire(self, helpers, row_num, identity, jwt_token,
              method, path_template, params):
        import time
        tab_data = self._tab

        try:
            path = path_template
            query_parts = []
            body_obj = {}

            for p in params:
                val = p["value"]
                if not val:
                    continue
                if p["in"] == "path":
                    path = path.replace("{%s}" % p["name"], val)
                elif p["in"] == "query":
                    query_parts.append("%s=%s" % (
                        helpers.urlEncode(p["name"]),
                        helpers.urlEncode(val)))
                elif p["in"] == "body":
                    body_obj[p["name"]] = val

            url_path = path
            if query_parts:
                url_path += "?" + "&".join(query_parts)

            full_url_str = self._base + url_path
            url_obj = java.net.URL(full_url_str)
            host = url_obj.getHost()
            port = url_obj.getPort()
            use_https = full_url_str.startswith("https")
            if port == -1:
                port = 443 if use_https else 80

            path_for_request = url_obj.getPath()
            if url_obj.getQuery():
                path_for_request += "?" + url_obj.getQuery()
            if not path_for_request:
                path_for_request = "/"

            headers = [
                "%s %s HTTP/1.1" % (method, path_for_request),
                "Host: %s" % host,
            ]
            if jwt_token:
                headers.append("Authorization: Bearer %s" % jwt_token)
            headers += [
                "User-Agent: %s" % self._user_agent,
                "Accept: */*",
                "Connection: close",
            ]

            body_bytes = None
            if body_obj and method in ("POST", "PUT", "PATCH"):
                body_str = json.dumps(body_obj)
                body_bytes = helpers.stringToBytes(body_str)
                headers.append("Content-Type: application/json")
                headers.append("Content-Length: %d" % len(body_str))

            request = helpers.buildHttpMessage(headers, body_bytes)
            http_service = helpers.buildHttpService(host, port, use_https)

            t0 = time.time()
            response = self._ext._callbacks.makeHttpRequest(http_service, request)
            elapsed = int((time.time() - t0) * 1000)

            resp_bytes = response.getResponse()
            if resp_bytes is None:
                status = "N/A"; size = 0; raw_resp = None
            else:
                resp_info = helpers.analyzeResponse(resp_bytes)
                status = resp_info.getStatusCode()
                size = len(resp_bytes)
                raw_resp = resp_bytes

            cur_row = row_num

            class _Add(Runnable):
                def __init__(s):
                    s.r = cur_row; s.id = identity; s.st = status
                    s.sz = size; s.el = elapsed
                    s.rq = request; s.rsp = raw_resp; s.svc = http_service
                def run(s):
                    tab_data["model"].addRow([
                        str(s.r), s.id, str(s.st), str(s.sz), str(s.el)])
                    tab_data["raw_requests"].append(s.rq)
                    tab_data["raw_responses"].append(s.rsp)
                    tab_data["http_services"].append(s.svc)

            SwingUtilities.invokeLater(_Add())

        except Exception as e:
            cur_row = row_num
            err_msg = str(e)

            class _Err(Runnable):
                def __init__(s):
                    s.r = cur_row; s.id = identity; s.err = err_msg
                def run(s):
                    tab_data["model"].addRow([
                        str(s.r), s.id, "ERR", "0", "0"])
                    tab_data["raw_requests"].append(None)
                    tab_data["raw_responses"].append(None)
                    tab_data["http_services"].append(None)

            SwingUtilities.invokeLater(_Err())


# ── Background request runner ──────────────────────────────────────────────

class _RequestRunner(Runnable):
    def __init__(self, extender, base, method, path_template, params, jwt_pairs, user_agent="SwaggerJWTTester-Burp/1.0"):
        self._ext = extender
        self._base = base
        self._method = method
        self._path = path_template
        self._params = params
        self._jwt_pairs = jwt_pairs  # list of (name, token)
        self._user_agent = user_agent

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[SwaggerJWTTester] %s" % msg)
        except Exception:
            pass

    def run(self):
        import time

        total = len(self._jwt_pairs) + 1  # +1 for unauthenticated

        try:
            self._log("Starting %d request(s)..." % total)
            row_num = 0

            # ── First: unauthenticated request (no JWT) ─────────────────
            row_num += 1
            try:
                result = self._doRequest(None)
                status, size, elapsed, body, req_text, raw_req, raw_resp, svc = result
                self._log("No-auth request done: status=%s" % str(status))

                class _AddNoAuth(Runnable):
                    def __init__(s):
                        s.r = row_num; s.st = status; s.sz = size
                        s.el = elapsed; s.b = body; s.rq = req_text
                        s.rr = raw_req; s.rsp = raw_resp; s.svc = svc
                    def run(s):
                        self._ext._appendResult(s.r, "<No Auth>", s.st, s.sz, s.el,
                            s.b, s.rq, s.rr, s.rsp, s.svc)

                SwingUtilities.invokeLater(_AddNoAuth())
            except Exception as e:
                self._log("No-auth request error: %s" % str(e))
                err_msg = str(e)

                class _AddNoAuthErr(Runnable):
                    def __init__(s):
                        s.r = row_num; s.err = err_msg
                    def run(s):
                        self._ext._appendResult(s.r, "<No Auth>", "ERR", 0, 0,
                            "Error: %s" % s.err)

                SwingUtilities.invokeLater(_AddNoAuthErr())

            # ── Then: one request per named JWT ──────────────────────────
            for i, (jwt_name, jwt_token) in enumerate(self._jwt_pairs):
                row_num += 1
                cur_row = row_num
                display_name = jwt_name
                try:
                    result = self._doRequest(jwt_token)
                    status, size, elapsed, body, req_text, raw_req, raw_resp, svc = result
                    self._log("[%s] done: status=%s" % (jwt_name, str(status)))

                    class _AddRow(Runnable):
                        def __init__(s):
                            s.r = cur_row; s.j = display_name; s.st = status
                            s.sz = size; s.el = elapsed; s.b = body; s.rq = req_text
                            s.rr = raw_req; s.rsp = raw_resp; s.svc = svc
                        def run(s):
                            self._ext._appendResult(s.r, s.j, s.st, s.sz, s.el,
                                s.b, s.rq, s.rr, s.rsp, s.svc)

                    SwingUtilities.invokeLater(_AddRow())
                except Exception as e:
                    self._log("[%s] error: %s" % (jwt_name, str(e)))
                    err_msg = str(e)

                    class _AddErr(Runnable):
                        def __init__(s):
                            s.r = cur_row; s.j = display_name; s.err = err_msg
                        def run(s):
                            self._ext._appendResult(s.r, s.j, "ERR", 0, 0,
                                "Error: %s" % s.err)

                    SwingUtilities.invokeLater(_AddErr())

        except Exception as e:
            self._log("FATAL error in runner: %s\n%s" % (str(e), traceback.format_exc()))

        class _Done(Runnable):
            def run(s):
                self._ext._sendBtn.setEnabled(True)
                self._ext._statusLabel.setText(
                    "Done — %d request(s) sent (1 unauthenticated + %d with JWT)." % (total, len(self._jwt_pairs)))
        SwingUtilities.invokeLater(_Done())

    def _doRequest(self, jwt):
        import time
        helpers = self._ext._helpers

        # ── Build URL path (substitute path params) ──────────────────────
        path = self._path
        query_parts = []
        body_obj = {}

        for p in self._params:
            val = p["value"]
            if not val:
                continue
            if p["in"] == "path":
                path = path.replace("{%s}" % p["name"], val)
            elif p["in"] == "query":
                query_parts.append("%s=%s" % (
                    helpers.urlEncode(p["name"]),
                    helpers.urlEncode(val)))
            elif p["in"] == "body":
                body_obj[p["name"]] = val

        url_path = path
        if query_parts:
            url_path += "?" + "&".join(query_parts)

        full_url_str = self._base + url_path
        self._log("  -> %s %s" % (self._method, full_url_str))

        # Parse host / port / protocol from base URL
        url_obj = java.net.URL(full_url_str)
        host = url_obj.getHost()
        port = url_obj.getPort()
        use_https = full_url_str.startswith("https")
        if port == -1:
            port = 443 if use_https else 80

        # ── Build raw HTTP request ───────────────────────────────────────
        path_for_request = url_obj.getPath()
        if url_obj.getQuery():
            path_for_request += "?" + url_obj.getQuery()
        if not path_for_request:
            path_for_request = "/"

        headers = [
            "%s %s HTTP/1.1" % (self._method, path_for_request),
            "Host: %s" % host,
        ]
        if jwt:
            headers.append("Authorization: Bearer %s" % jwt)
        headers += [
            "User-Agent: %s" % self._user_agent,
            "Accept: */*",
            "Connection: close",
        ]

        body_bytes = None
        if body_obj and self._method in ("POST", "PUT", "PATCH"):
            body_str = json.dumps(body_obj)
            body_bytes = helpers.stringToBytes(body_str)
            headers.append("Content-Type: application/json")
            headers.append("Content-Length: %d" % len(body_str))

        request = helpers.buildHttpMessage(headers, body_bytes)

        # Capture the raw request as readable text for display
        request_str = helpers.bytesToString(request)

        # ── Send via Burp ────────────────────────────────────────────────
        http_service = helpers.buildHttpService(host, port, use_https)

        t0 = time.time()
        response = self._ext._callbacks.makeHttpRequest(http_service, request)
        elapsed = int((time.time() - t0) * 1000)

        resp_bytes = response.getResponse()
        if resp_bytes is None:
            return ("N/A", 0, elapsed, "<No response received>",
                    request_str, request, None, http_service)

        resp_info = helpers.analyzeResponse(resp_bytes)
        status = resp_info.getStatusCode()
        body_offset = resp_info.getBodyOffset()
        body = helpers.bytesToString(resp_bytes[body_offset:])
        size = len(resp_bytes)

        return (status, size, elapsed, body,
                request_str, request, resp_bytes, http_service)

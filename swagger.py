from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTextArea, JScrollPane,
    JTable, JComboBox, JFileChooser, JSplitPane, BorderFactory,
    JOptionPane, SwingUtilities, BoxLayout, Box, JTabbedPane,
    JProgressBar, JCheckBox
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.border import TitledBorder
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt import FlowLayout, Dimension, Color, Font, GridLayout
from java.awt.event import ActionListener, MouseAdapter
from java.io import File
from java.lang import Runnable, String, Thread as JThread
from java.util.concurrent import Semaphore as JSemaphore
import java.net
import json
import traceback


# -- Helpers ------------------------------------------------------------------

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


# -- Editable-column JTable (Jython-safe override) -------------------------

class _EditableTable(JTable):
    """JTable where only specific columns are editable.
    Overriding isCellEditable on JTable is more reliable in Jython
    than overriding it on DefaultTableModel."""
    def __init__(self, model, editable_cols):
        JTable.__init__(self, model)
        self._editable = editable_cols  # list or set of column indices

    def isCellEditable(self, row, col):
        return col in self._editable


# -- Status code cell renderer ----------------------------------------------

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


# -- Main Extension ---------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IMessageEditorController):

    # -- IBurpExtender ------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Swagger_Tester")

        self._spec = None
        self._endpoints = []
        self._responses = []     # response body string per row
        self._requests = []      # request text per row
        self._raw_requests = []  # raw request byte[] per row
        self._raw_responses = [] # full raw response byte[] per row
        self._http_services = [] # IHttpService per row
        self._currentRow = -1    # currently selected result row
        self._autoScanTabs = []  # list of per-endpoint tab data dicts
        self._pauseSemaphore = JSemaphore(0)  # for pause/resume
        self._requestCounter = 0              # total requests sent in current run
        self._globalParams = {}               # {param_name: user-set value}
        self._autoScanStopped = False         # stop flag for auto scan
        self._autoScanPaused = False          # pause flag for auto scan
        self._wordlist = []                   # loaded wordlist for fuzz scan
        self._fuzzTargetType = ""             # type to fuzz

        SwingUtilities.invokeLater(self._buildUI)

    # -- ITab ---------------------------------------------------------------
    def getTabCaption(self):
        return "Swagger_Tester"

    def getUiComponent(self):
        return self._mainPanel

    # -- IMessageEditorController -------------------------------------------
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

    # -- UI construction ----------------------------------------------------
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout(0, 4))
        self._mainPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # ==================================================================
        # Top-level tabbed pane: Configuration | Requests
        # ==================================================================
        self._topTabs = JTabbedPane()

        # ==================================================================
        #  TAB 1: CONFIGURATION
        # ==================================================================
        configTab = JPanel(BorderLayout(0, 4))
        configTab.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # -- Swagger load + Base URL + Session ----------------------------
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

        self._userAgentField = JTextField("Swagger_Tester/1.0", 40)
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

        # -- Center: endpoint selector + params + JWTs --------------------
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

        # -- Params table (endpoint parameters only) --------------------
        paramCols = ["Name", "In", "Type", "Required", "Value"]
        self._paramModel = DefaultTableModel(paramCols, 0)
        self._paramTable = _EditableTable(self._paramModel, [4])
        self._paramTable.setRowSorter(TableRowSorter(self._paramModel))
        self._paramTable.getColumnModel().getColumn(0).setPreferredWidth(140)
        self._paramTable.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(2).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(3).setPreferredWidth(60)
        self._paramTable.getColumnModel().getColumn(4).setPreferredWidth(250)
        paramScroll = JScrollPane(self._paramTable)
        paramScroll.setBorder(BorderFactory.createTitledBorder("Endpoint Parameters"))
        paramScroll.setMinimumSize(Dimension(200, 100))
        configSplit.setLeftComponent(paramScroll)

        # -- JWT panel ----------------------------------------------------
        jwtPanel = JPanel(BorderLayout(0, 2))
        jwtPanel.setBorder(BorderFactory.createTitledBorder("Auth Identities & Session Refresh"))

        # Split: auth table (top) + refresh config (bottom)
        authSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        authSplit.setResizeWeight(0.55)
        authSplit.setDividerSize(6)
        authSplit.setContinuousLayout(True)

        # -- Auth table with Login Body column ----------------------------
        authTopPanel = JPanel(BorderLayout(0, 2))
        jwtCols = ["Name", "Type", "Value", "Login Body"]
        self._jwtModel = DefaultTableModel(jwtCols, 0)
        self._jwtTable = _EditableTable(self._jwtModel, [0, 1, 2, 3])
        self._jwtTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._jwtTable.getColumnModel().getColumn(0).setPreferredWidth(65)
        self._jwtTable.getColumnModel().getColumn(1).setPreferredWidth(50)
        self._jwtTable.getColumnModel().getColumn(2).setPreferredWidth(150)
        self._jwtTable.getColumnModel().getColumn(3).setPreferredWidth(200)
        self._jwtTable.setToolTipText(
            "Login Body: JSON sent to login URL to get a fresh token/cookie for this identity")
        authTopPanel.add(JScrollPane(self._jwtTable), BorderLayout.CENTER)

        jwtBtnRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        jwtBtnRow.add(JButton("Add Bearer", actionPerformed=self._onAddBearer))
        jwtBtnRow.add(JButton("Add Cookie", actionPerformed=self._onAddCookie))
        jwtBtnRow.add(JButton("Edit Login", actionPerformed=self._onEditLoginBody))
        jwtBtnRow.add(JButton("Remove", actionPerformed=self._onRemoveJWT))
        jwtBtnRow.add(JButton("Clear All", actionPerformed=lambda e: self._jwtModel.setRowCount(0)))
        authTopPanel.add(jwtBtnRow, BorderLayout.SOUTH)
        authTopPanel.setMinimumSize(Dimension(200, 80))
        authSplit.setTopComponent(authTopPanel)

        # -- Session Refresh config ---------------------------------------
        refreshPanel = JPanel(GridBagLayout())
        refreshPanel.setBorder(BorderFactory.createTitledBorder("Session Refresh"))
        rgbc = GridBagConstraints()
        rgbc.insets = Insets(2, 4, 2, 4)
        rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.anchor = GridBagConstraints.WEST

        rgbc.gridx = 0; rgbc.gridy = 0; rgbc.weightx = 0
        refreshPanel.add(JLabel("Mode:"), rgbc)
        self._loginModeCombo = JComboBox([
            "Direct POST (JSON)",
            "Direct POST (Form-encoded)",
            "Keycloak Browser Flow"])
        self._loginModeCombo.setToolTipText(
            "JSON/Form: single POST to login URL. "
            "Keycloak: follows full redirect chain automatically.")
        rgbc.gridx = 1; rgbc.weightx = 1.0; rgbc.gridwidth = 3
        refreshPanel.add(self._loginModeCombo, rgbc)
        rgbc.gridwidth = 1

        rgbc.gridx = 0; rgbc.gridy = 1; rgbc.weightx = 0
        refreshPanel.add(JLabel("Login URL:"), rgbc)
        self._loginUrlField = JTextField("", 25)
        self._loginUrlField.setToolTipText(
            "Direct: POST URL (e.g. /auth/login). "
            "Keycloak: app URL that redirects to KC (e.g. /auth/keycloak/login) "
            "or token endpoint (e.g. /realms/myrealm/protocol/openid-connect/token)")
        rgbc.gridx = 1; rgbc.weightx = 1.0; rgbc.gridwidth = 3
        refreshPanel.add(self._loginUrlField, rgbc)
        rgbc.gridwidth = 1

        rgbc.gridx = 0; rgbc.gridy = 2; rgbc.weightx = 0
        refreshPanel.add(JLabel("Extract:"), rgbc)
        self._extractCombo = JComboBox(["Set-Cookie header", "JSON body field"])
        rgbc.gridx = 1; rgbc.weightx = 0.5
        refreshPanel.add(self._extractCombo, rgbc)

        rgbc.gridx = 2; rgbc.weightx = 0
        refreshPanel.add(JLabel("Field:"), rgbc)
        self._extractFieldName = JTextField("access_token", 10)
        self._extractFieldName.setToolTipText("JSON field path (e.g. access_token, data.jwt)")
        rgbc.gridx = 3; rgbc.weightx = 0.5
        refreshPanel.add(self._extractFieldName, rgbc)

        rgbc.gridx = 0; rgbc.gridy = 3; rgbc.weightx = 0; rgbc.gridwidth = 4
        refreshBtnRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self._refreshAllBtn = JButton("Refresh All Sessions",
                                       actionPerformed=self._onRefreshAllSessions)
        refreshBtnRow.add(self._refreshAllBtn)
        self._autoRefreshCb = JCheckBox("Auto-refresh before scan")
        self._autoRefreshCb.setToolTipText("Refresh all sessions once before auto scan starts")
        refreshBtnRow.add(self._autoRefreshCb)
        self._perRequestRefreshCb = JCheckBox("Refresh per request")
        self._perRequestRefreshCb.setToolTipText(
            "Perform a fresh login flow before EACH individual request (slower but handles short-lived sessions)")
        refreshBtnRow.add(self._perRequestRefreshCb)
        refreshPanel.add(refreshBtnRow, rgbc)

        refreshPanel.setMinimumSize(Dimension(200, 70))
        authSplit.setBottomComponent(refreshPanel)

        jwtPanel.add(authSplit, BorderLayout.CENTER)

        configSplit.setRightComponent(jwtPanel)
        jwtPanel.setMinimumSize(Dimension(200, 150))
        centerPanel.add(configSplit, BorderLayout.CENTER)

        # Send button row
        sendRow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))

        sendRow.add(JLabel("Batch size:"))
        self._batchSizeField = JTextField("0", 4)
        self._batchSizeField.setToolTipText("Pause after N requests (0 = no limit)")
        sendRow.add(self._batchSizeField)

        self._resumeBtn = JButton("Resume")
        self._resumeBtn.setEnabled(False)
        self._resumeBtn.addActionListener(lambda e: self._onResume())
        sendRow.add(self._resumeBtn)

        self._pauseScanBtn = JButton("Pause Scan")
        self._pauseScanBtn.setEnabled(False)
        self._pauseScanBtn.addActionListener(lambda e: self._onPauseScan())
        sendRow.add(self._pauseScanBtn)

        self._stopScanBtn = JButton("Stop Scan")
        self._stopScanBtn.setEnabled(False)
        self._stopScanBtn.setForeground(Color(180, 0, 0))
        self._stopScanBtn.addActionListener(lambda e: self._onStopScan())
        sendRow.add(self._stopScanBtn)

        self._bypassConfirmCb = JCheckBox("Skip confirm for POST/PUT/PATCH/DELETE")
        self._bypassConfirmCb.setSelected(True)
        self._bypassConfirmCb.setToolTipText("Auto-send mutating requests without waiting for confirmation")
        sendRow.add(self._bypassConfirmCb)

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

        # ==================================================================
        #  TAB 2: PARAMETERS (global parameter values)
        # ==================================================================
        paramsTab = JPanel(BorderLayout(0, 4))
        paramsTab.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # Button row
        paramsBtnRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        self._autoFillBtn = JButton("Auto-fill from Proxy History",
                                     actionPerformed=self._onAutoFillGlobalParams)
        paramsBtnRow.add(self._autoFillBtn)
        self._applyGlobalBtn = JButton("Apply Values to All Endpoints",
                                        actionPerformed=self._onApplyGlobalParams)
        paramsBtnRow.add(self._applyGlobalBtn)
        paramsTab.add(paramsBtnRow, BorderLayout.NORTH)

        # Split: global param table (left/top) + found proxy values (right/bottom)
        paramGlobalSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        paramGlobalSplit.setResizeWeight(0.55)
        paramGlobalSplit.setDividerSize(8)
        paramGlobalSplit.setContinuousLayout(True)

        # Global params table
        gpCols = ["Parameter", "In", "Type", "Required", "Endpoints", "Found", "Value"]
        self._globalParamModel = DefaultTableModel(gpCols, 0)
        self._globalParamTable = _EditableTable(self._globalParamModel, [6])
        self._globalParamTable.getColumnModel().getColumn(0).setPreferredWidth(130)
        self._globalParamTable.getColumnModel().getColumn(1).setPreferredWidth(50)
        self._globalParamTable.getColumnModel().getColumn(2).setPreferredWidth(55)
        self._globalParamTable.getColumnModel().getColumn(3).setPreferredWidth(50)
        self._globalParamTable.getColumnModel().getColumn(4).setPreferredWidth(85)
        self._globalParamTable.getColumnModel().getColumn(5).setPreferredWidth(40)
        self._globalParamTable.getColumnModel().getColumn(6).setPreferredWidth(180)
        self._globalParamTable.addMouseListener(_GlobalParamClickListener(self))
        self._globalParamSorter = TableRowSorter(self._globalParamModel)
        self._globalParamTable.setRowSorter(self._globalParamSorter)
        gpScroll = JScrollPane(self._globalParamTable)
        gpScroll.setBorder(BorderFactory.createTitledBorder(
            "All Parameters (edit Value, then click 'Apply Values to All Endpoints')"))
        gpScroll.setMinimumSize(Dimension(200, 100))
        paramGlobalSplit.setLeftComponent(gpScroll)

        # Found proxy values for selected param
        pvCols = ["Value", "Source URL", "Found In"]
        self._globalProxyModel = DefaultTableModel(pvCols, 0)
        self._globalProxyTable = _EditableTable(self._globalProxyModel, [])
        self._globalProxyTable.getColumnModel().getColumn(0).setPreferredWidth(200)
        self._globalProxyTable.getColumnModel().getColumn(1).setPreferredWidth(250)
        self._globalProxyTable.getColumnModel().getColumn(2).setPreferredWidth(100)
        self._globalProxyTable.addMouseListener(_GlobalProxyValClickListener(self))
        self._globalProxySorter = TableRowSorter(self._globalProxyModel)
        self._globalProxyTable.setRowSorter(self._globalProxySorter)
        pvScroll = JScrollPane(self._globalProxyTable)
        pvScroll.setBorder(BorderFactory.createTitledBorder(
            "Proxy values for selected parameter (double-click to use)"))
        pvScroll.setMinimumSize(Dimension(200, 100))
        paramGlobalSplit.setRightComponent(pvScroll)

        paramsTab.add(paramGlobalSplit, BorderLayout.CENTER)

        # -- Bulk fill by type panel --------------------------------------
        bulkPanel = JPanel(GridBagLayout())
        bulkPanel.setBorder(BorderFactory.createTitledBorder(
            "Bulk Fill by Type -- set placeholder values for empty required params"))
        bgbc = GridBagConstraints()
        bgbc.insets = Insets(3, 4, 3, 4)
        bgbc.fill = GridBagConstraints.HORIZONTAL
        bgbc.anchor = GridBagConstraints.WEST

        bgbc.gridx = 0; bgbc.gridy = 0; bgbc.weightx = 0
        bulkPanel.add(JLabel("Type:"), bgbc)
        self._bulkTypeCombo = JComboBox(["string", "integer", "number", "boolean", "array", "object"])
        self._bulkTypeCombo.setEditable(True)
        bgbc.gridx = 1; bgbc.weightx = 0.3
        bulkPanel.add(self._bulkTypeCombo, bgbc)

        bgbc.gridx = 2; bgbc.weightx = 0
        bulkPanel.add(JLabel("  Value:"), bgbc)
        self._bulkValueField = JTextField("", 20)
        self._bulkValueField.setToolTipText("Placeholder value to set for all matching parameters")
        bgbc.gridx = 3; bgbc.weightx = 0.7
        bulkPanel.add(self._bulkValueField, bgbc)

        bgbc.gridx = 0; bgbc.gridy = 1; bgbc.gridwidth = 4; bgbc.weightx = 1.0
        bulkOptRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        self._bulkReplaceExistingCb = JCheckBox("Replace existing values for this type")
        self._bulkReplaceExistingCb.setToolTipText("Also overwrite params that already have a value")
        bulkOptRow.add(self._bulkReplaceExistingCb)
        self._bulkIncludeOptionalCb = JCheckBox("Include optional parameters")
        self._bulkIncludeOptionalCb.setToolTipText("Apply to optional params too, not just required")
        bulkOptRow.add(self._bulkIncludeOptionalCb)
        bulkApplyBtn = JButton("Apply to Matching Params",
                               actionPerformed=self._onBulkFillByType)
        bulkOptRow.add(bulkApplyBtn)
        bulkPanel.add(bulkOptRow, bgbc)

        # Wordlist / Fuzz row
        bgbc.gridx = 0; bgbc.gridy = 2; bgbc.gridwidth = 4; bgbc.weightx = 1.0
        fuzzRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        fuzzRow.add(JLabel("Wordlist:"))
        loadWlBtn = JButton("Load Wordlist",
                            actionPerformed=self._onLoadWordlist)
        loadWlBtn.setToolTipText("Load a text file with one value per line (e.g. dic.txt)")
        fuzzRow.add(loadWlBtn)
        self._wordlistLabel = JLabel("  (none loaded)  ")
        fuzzRow.add(self._wordlistLabel)
        self._fuzzScanBtn = JButton("Fuzz Scan All Endpoints",
                                     actionPerformed=self._onFuzzScan)
        self._fuzzScanBtn.setEnabled(False)
        self._fuzzScanBtn.setToolTipText(
            "For each endpoint, send one request per wordlist value (for selected type) x each identity")
        fuzzRow.add(self._fuzzScanBtn)
        bulkPanel.add(fuzzRow, bgbc)

        paramsTab.add(bulkPanel, BorderLayout.SOUTH)

        self._topTabs.addTab("Parameters", paramsTab)

        # ==================================================================
        #  TAB 3: REQUESTS
        # ==================================================================
        requestsTab = JPanel(BorderLayout(0, 4))
        requestsTab.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # -- Sub-tabs: Manual + Auto Scan endpoint tabs -------------------
        self._resultsTabbedPane = JTabbedPane()
        self._resultsTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

        # -- Manual results sub-tab (just the results grid) ---------------
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
        self._resultSorter = TableRowSorter(self._resultModel)
        self._resultTable.setRowSorter(self._resultSorter)
        resultScroll = JScrollPane(self._resultTable)
        self._resultsTabbedPane.addTab("Manual", resultScroll)

        # -- Shared Burp message editors (below the sub-tabs) -------------
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

        # -- Vertical split: sub-tabs on top, editors on bottom -----------
        requestsSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        requestsSplit.setResizeWeight(0.45)
        requestsSplit.setDividerSize(8)
        requestsSplit.setContinuousLayout(True)
        self._resultsTabbedPane.setMinimumSize(Dimension(200, 80))
        reqRespSplit.setMinimumSize(Dimension(200, 100))
        requestsSplit.setTopComponent(self._resultsTabbedPane)
        requestsSplit.setBottomComponent(reqRespSplit)

        requestsTab.add(requestsSplit, BorderLayout.CENTER)

        self._topTabs.addTab("Requests", requestsTab)

        # ==================================================================

        self._mainPanel.add(self._topTabs, BorderLayout.CENTER)

        # -- Status bar ---------------------------------------------------
        self._statusLabel = JLabel("Ready -- load a Swagger JSON to begin.")
        self._statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 4, 2, 4))
        self._mainPanel.add(self._statusLabel, BorderLayout.SOUTH)

        self._callbacks.addSuiteTab(self)

    # -- JSON repair helper -------------------------------------------------

    def _tryRepairJson(self, raw):
        """Try to fix malformed JSON: truncated files or concatenated objects."""
        raw = raw.rstrip()

        # -- Case 1: Concatenated JSON objects ----------------------------
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

        # -- Case 2: Truncated JSON (missing closing braces/brackets) -----
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
            return None  # balanced already -- error is something else

        suffix = ''.join(reversed(stack))
        try:
            return json.loads(raw + suffix)
        except Exception:
            return None

    # -- Event handlers -----------------------------------------------------

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
                    "Warning -- Auto-repaired",
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
        self._populateGlobalParams()

    def _onEndpointChanged(self):
        idx = self._endpointCombo.getSelectedIndex()
        if idx < 0 or idx >= len(self._endpoints):
            return
        _, _, _, params = self._endpoints[idx]
        self._paramModel.setRowCount(0)
        for p in params:
            self._paramModel.addRow([
                p["name"],
                p["in"],
                p["type"],
                str(p["required"]),
                str(p["default"]) if p["default"] is not None else "",
            ])

    def _onAddBearer(self, event):
        name = JOptionPane.showInputDialog(self._mainPanel,
            "Enter a name (e.g. admin, user1, guest):",
            "Identity Name", JOptionPane.PLAIN_MESSAGE)
        if name is None:
            return
        name = name.strip() if name else "ID-%d" % (self._jwtModel.getRowCount() + 1)
        if not name:
            name = "ID-%d" % (self._jwtModel.getRowCount() + 1)

        token = JOptionPane.showInputDialog(self._mainPanel,
            "Paste the Bearer token for '%s':" % name,
            "Add Bearer Token", JOptionPane.PLAIN_MESSAGE)
        if token and token.strip():
            self._jwtModel.addRow([name, "Bearer", token.strip(), ""])

    def _onAddCookie(self, event):
        name = JOptionPane.showInputDialog(self._mainPanel,
            "Enter a name (e.g. admin, user1, guest):",
            "Identity Name", JOptionPane.PLAIN_MESSAGE)
        if name is None:
            return
        name = name.strip() if name else "ID-%d" % (self._jwtModel.getRowCount() + 1)
        if not name:
            name = "ID-%d" % (self._jwtModel.getRowCount() + 1)

        cookie = JOptionPane.showInputDialog(self._mainPanel,
            "Paste the Cookie header value for '%s'\n(e.g. JSESSIONID=abc123; other=val):" % name,
            "Add Cookie", JOptionPane.PLAIN_MESSAGE)
        if cookie and cookie.strip():
            self._jwtModel.addRow([name, "Cookie", cookie.strip(), ""])

    def _onEditLoginBody(self, event):
        """Open a dialog to edit the Login Body for the selected identity."""
        row = self._jwtTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an identity row first.", "Info",
                JOptionPane.INFORMATION_MESSAGE)
            return

        name = str(self._jwtModel.getValueAt(row, 0) or "")
        current = str(self._jwtModel.getValueAt(row, 3) or "")

        # Create a dialog with a text area
        textArea = JTextArea(8, 45)
        textArea.setLineWrap(True)
        textArea.setWrapStyleWord(True)
        textArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        textArea.setText(current if current else '{"username": "", "password": "", "otp_secret": ""}')
        scrollPane = JScrollPane(textArea)
        scrollPane.setBorder(BorderFactory.createTitledBorder(
            "Login Body for '%s'" % name))

        helpLabel = JLabel(
            "<html><small>"
            "JSON: {\"username\": \"user@co.com\", \"password\": \"pass\", \"otp_secret\": \"BASE32KEY\"}<br>"
            "Form: grant_type=password&client_id=app&username=admin&password=pass<br>"
            "Keycloak: just username + password. Add \"otp_secret\": \"BASE32KEY\" ONLY if account has 2FA."
            "</small></html>")

        panel = JPanel(BorderLayout(0, 4))
        panel.add(scrollPane, BorderLayout.CENTER)
        panel.add(helpLabel, BorderLayout.SOUTH)

        result = JOptionPane.showConfirmDialog(self._mainPanel, panel,
            "Edit Login Body -- %s" % name,
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)

        if result == JOptionPane.OK_OPTION:
            self._jwtModel.setValueAt(textArea.getText().strip(), row, 3)

    def _onResume(self):
        """Release the pause semaphore so the runner continues."""
        self._autoScanPaused = False
        self._resumeBtn.setEnabled(False)
        self._pauseScanBtn.setEnabled(True)
        self._statusLabel.setText("Resuming...")
        self._pauseSemaphore.release()

    def _onPauseScan(self):
        """Pause the auto scan."""
        self._autoScanPaused = True
        self._pauseScanBtn.setEnabled(False)
        self._resumeBtn.setEnabled(True)
        self._statusLabel.setText("Scan paused -- click Resume to continue.")

    def _onStopScan(self):
        """Stop the auto scan permanently."""
        self._autoScanStopped = True
        self._autoScanPaused = False
        self._pauseScanBtn.setEnabled(False)
        self._stopScanBtn.setEnabled(False)
        self._resumeBtn.setEnabled(False)
        # Release semaphore in case thread is blocked on pause
        self._pauseSemaphore.release()
        self._statusLabel.setText("Scan stopped by user.")

    # -- Session Refresh ----------------------------------------------------

    def _onRefreshAllSessions(self, event):
        """Refresh auth values for all identities using the login macro."""
        login_url = self._loginUrlField.getText().strip()
        if not login_url:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Enter a Login URL first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        if self._jwtTable.isEditing():
            self._jwtTable.getCellEditor().stopCellEditing()

        count = self._jwtModel.getRowCount()
        if count == 0:
            return

        self._refreshAllBtn.setEnabled(False)
        self._statusLabel.setText("Refreshing %d session(s)..." % count)

        runner = _SessionRefreshRunner(self, login_url)
        JThread(runner).start()

    def _doRefreshSession(self, login_url, login_body, auth_type):
        """Execute a login flow and extract the token/cookie. Returns new value or None."""
        mode = self._loginModeCombo.getSelectedItem()

        if mode == "Keycloak Browser Flow":
            return self._doKeycloakFlow(login_url, login_body)
        else:
            content_type = "application/json" if "JSON" in mode else "application/x-www-form-urlencoded"
            return self._doDirectLogin(login_url, login_body, content_type)

    def _doDirectLogin(self, login_url, login_body, content_type):
        """Single POST login request."""
        helpers = self._helpers
        try:
            url_obj = java.net.URL(login_url)
            host = url_obj.getHost()
            port = url_obj.getPort()
            use_https = login_url.startswith("https")
            if port == -1:
                port = 443 if use_https else 80

            path = url_obj.getPath()
            if url_obj.getQuery():
                path += "?" + url_obj.getQuery()
            if not path:
                path = "/"

            headers = [
                "POST %s HTTP/1.1" % path,
                "Host: %s" % host,
                "Content-Type: %s" % content_type,
                "User-Agent: %s" % self._userAgentField.getText().strip(),
                "Accept: */*",
                "Connection: close",
            ]

            body_bytes = None
            if login_body:
                body_bytes = helpers.stringToBytes(login_body)
                headers.append("Content-Length: %d" % len(login_body))

            request = helpers.buildHttpMessage(headers, body_bytes)
            http_service = helpers.buildHttpService(host, port, use_https)

            response = self._callbacks.makeHttpRequest(http_service, request)
            resp_bytes = response.getResponse()
            if resp_bytes is None:
                return None

            return self._extractAuthValue(resp_bytes)

        except Exception as e:
            self._callbacks.printOutput("[SessionRefresh] Direct login error: %s" % str(e))
            return None

    def _doKeycloakFlow(self, login_url, login_body):
        """Full Keycloak multi-step browser flow:
        Step 1: GET login URL -> follow redirects to Keycloak
        Step 2: Parse username form -> POST username
        Step 3: Parse password form -> POST password
        Step 4: If OTP form -> generate TOTP -> POST OTP
        Step 5: Follow redirects back -> collect session cookie
        """
        helpers = self._helpers
        import re

        # Parse credentials from login_body
        try:
            creds = json.loads(login_body)
        except Exception:
            creds = {}
            for pair in login_body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    creds[k.strip()] = v.strip()

        username = creds.get("username", creds.get("user", creds.get("email", "")))
        password = creds.get("password", creds.get("pass", ""))
        otp_secret = creds.get("otp_secret", creds.get("totp_secret", ""))

        if not username or not password:
            self._callbacks.printOutput(
                "[Keycloak] Login body must contain username and password fields")
            return None

        self._callbacks.printOutput("[Keycloak] Starting multi-step flow for '%s'..." % username)
        if otp_secret:
            self._callbacks.printOutput("[Keycloak]   OTP secret provided -- will generate TOTP code")

        cookie_jar = {}  # {name: value}

        try:
            # == Step 1: GET login URL -> follow redirects to Keycloak ======
            current_url = login_url
            resp_bytes = self._kcFollowRedirects(current_url, cookie_jar)
            if resp_bytes is None:
                return None

            # == Step 2: Parse & POST username form ========================
            form_action = self._kcFindFormAction(resp_bytes, current_url)
            if not form_action:
                self._callbacks.printOutput("[Keycloak] ERROR: No login form found")
                return None

            # Check what fields the form needs
            body_offset = helpers.analyzeResponse(resp_bytes).getBodyOffset()
            html = helpers.bytesToString(resp_bytes[body_offset:])
            page_id = self._kcGetPageId(html)
            self._callbacks.printOutput("[Keycloak]   Page: %s" % page_id)

            if "username" in page_id or self._kcHasField(html, "username"):
                # Username-only form (login-login-username)
                post_body = "username=%s" % helpers.urlEncode(username)
                self._callbacks.printOutput("[Keycloak]   POST username to %s" % form_action[:80])

                resp_bytes, _ = self._kcRequest(
                    "POST", form_action, post_body,
                    "application/x-www-form-urlencoded", cookie_jar)
                if resp_bytes is None:
                    return None
                resp_info = helpers.analyzeResponse(resp_bytes)
                self._kcCollectCookies(resp_info, cookie_jar)

                # Follow any redirects
                resp_bytes = self._kcFollowIfRedirect(resp_bytes, form_action, cookie_jar)

                # Now parse the next form (should be password)
                form_action = self._kcFindFormAction(resp_bytes, form_action)
                if not form_action:
                    self._callbacks.printOutput("[Keycloak] ERROR: No password form found after username step")
                    return None

                html = helpers.bytesToString(
                    resp_bytes[helpers.analyzeResponse(resp_bytes).getBodyOffset():])
                page_id = self._kcGetPageId(html)
                self._callbacks.printOutput("[Keycloak]   Page: %s" % page_id)

            # == Step 3: POST password =====================================
            if "login" in page_id or self._kcHasField(html, "password"):
                # Extract hidden credentialId if present
                cred_id = self._kcGetHiddenField(html, "credentialId")
                post_body = "password=%s" % helpers.urlEncode(password)
                if cred_id:
                    post_body += "&credentialId=%s" % helpers.urlEncode(cred_id)

                self._callbacks.printOutput("[Keycloak]   POST password...")

                resp_bytes, _ = self._kcRequest(
                    "POST", form_action, post_body,
                    "application/x-www-form-urlencoded", cookie_jar)
                if resp_bytes is None:
                    return None
                resp_info = helpers.analyzeResponse(resp_bytes)
                self._kcCollectCookies(resp_info, cookie_jar)

                resp_bytes = self._kcFollowIfRedirect(resp_bytes, form_action, cookie_jar)

            # == Step 4: OTP if required ===================================
            html = helpers.bytesToString(
                resp_bytes[helpers.analyzeResponse(resp_bytes).getBodyOffset():])
            page_id = self._kcGetPageId(html)
            self._callbacks.printOutput("[Keycloak]   Page: %s" % page_id)

            if "otp" in page_id or self._kcHasField(html, "otp"):
                if not otp_secret:
                    self._callbacks.printOutput(
                        "[Keycloak] ERROR: OTP required but no otp_secret in login body. "
                        "Add \"otp_secret\": \"YOUR_BASE32_SECRET\" to the Login Body.")
                    return None

                form_action = self._kcFindFormAction(resp_bytes, form_action,
                    form_ids=["kc-otp-login-form", "kc-form-login"])
                if not form_action:
                    self._callbacks.printOutput("[Keycloak] ERROR: No OTP form found")
                    return None

                # Generate TOTP code
                totp_code = self._generateTOTP(otp_secret)
                self._callbacks.printOutput("[Keycloak]   Generated TOTP: %s" % totp_code)

                # Extract hidden selectedCredentialId
                sel_cred = self._kcGetHiddenField(html, "selectedCredentialId")
                post_body = "otp=%s" % helpers.urlEncode(totp_code)
                if sel_cred:
                    post_body = "selectedCredentialId=%s&%s" % (
                        helpers.urlEncode(sel_cred), post_body)

                self._callbacks.printOutput("[Keycloak]   POST OTP...")
                resp_bytes, _ = self._kcRequest(
                    "POST", form_action, post_body,
                    "application/x-www-form-urlencoded", cookie_jar)
                if resp_bytes is None:
                    return None
                resp_info = helpers.analyzeResponse(resp_bytes)
                self._kcCollectCookies(resp_info, cookie_jar)

            # == Step 5: Follow all redirects back to the app ==============
            resp_bytes = self._kcFollowIfRedirect(resp_bytes, form_action or login_url, cookie_jar)

            # == Step 6: Extract result ====================================
            extract_mode = self._extractCombo.getSelectedItem()

            if extract_mode == "Set-Cookie header":
                if cookie_jar:
                    # Filter to just the app cookies (session_id typically)
                    result = "; ".join("%s=%s" % (k, v) for k, v in cookie_jar.items()
                                      if not k.startswith("KC_") and k not in (
                                          "AUTH_SESSION_ID", "KEYCLOAK_IDENTITY",
                                          "KEYCLOAK_SESSION", "KC_AUTH_SESSION_HASH",
                                          "KC_RESTART"))
                    if not result:
                        # If filtering removed everything, return all
                        result = "; ".join("%s=%s" % (k, v) for k, v in cookie_jar.items())
                    self._callbacks.printOutput(
                        "[Keycloak] Success! Cookies: %s" % (
                            result[:80] + "..." if len(result) > 80 else result))
                    return result
            elif extract_mode == "JSON body field":
                return self._extractJsonField(resp_bytes)

        except Exception as e:
            self._callbacks.printOutput("[Keycloak] Error: %s" % str(e))
            import traceback
            self._callbacks.printOutput(traceback.format_exc())

        return None

    def _kcFollowRedirects(self, start_url, cookie_jar, max_redir=10):
        """GET a URL and follow all redirects. Returns final response bytes."""
        helpers = self._helpers
        current_url = start_url
        resp_bytes = None

        for _ in range(max_redir):
            self._callbacks.printOutput("[Keycloak]   GET %s" % current_url[:100])
            resp_bytes, _ = self._kcRequest("GET", current_url, None, None, cookie_jar)
            if resp_bytes is None:
                return None
            resp_info = helpers.analyzeResponse(resp_bytes)
            self._kcCollectCookies(resp_info, cookie_jar)
            status = resp_info.getStatusCode()

            if status in (301, 302, 303, 307, 308):
                location = self._kcGetHeader(resp_info, "Location")
                if location:
                    current_url = self._kcResolveUrl(current_url, location)
                    continue
            break
        return resp_bytes

    def _kcFollowIfRedirect(self, resp_bytes, base_url, cookie_jar, max_redir=10):
        """If response is a redirect, follow it. Otherwise return as-is."""
        helpers = self._helpers
        for _ in range(max_redir):
            resp_info = helpers.analyzeResponse(resp_bytes)
            status = resp_info.getStatusCode()
            if status not in (301, 302, 303, 307, 308):
                return resp_bytes
            location = self._kcGetHeader(resp_info, "Location")
            if not location:
                return resp_bytes
            redirect_url = self._kcResolveUrl(base_url, location)
            self._callbacks.printOutput("[Keycloak]   Redirect -> %s" % redirect_url[:100])
            resp_bytes, _ = self._kcRequest("GET", redirect_url, None, None, cookie_jar)
            if resp_bytes is None:
                return None
            resp_info = helpers.analyzeResponse(resp_bytes)
            self._kcCollectCookies(resp_info, cookie_jar)
            base_url = redirect_url
        return resp_bytes

    def _kcFindFormAction(self, resp_bytes, base_url, form_ids=None):
        """Find the action URL of a Keycloak login form in the HTML response."""
        import re
        helpers = self._helpers
        body_offset = helpers.analyzeResponse(resp_bytes).getBodyOffset()
        html = helpers.bytesToString(resp_bytes[body_offset:])

        if form_ids is None:
            form_ids = ["kc-form-login", "kc-otp-login-form"]

        for form_id in form_ids:
            # Try id before action
            m = re.search(
                r'<form[^>]*id=[\x22\x27]%s[\x22\x27][^>]*action=[\x22\x27]([^\x22\x27]+)[\x22\x27]' % re.escape(form_id), html)
            if not m:
                # Try action before id
                m = re.search(
                    r'<form[^>]*action=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*id=[\x22\x27]%s[\x22\x27]' % re.escape(form_id), html)
            if m:
                action = m.group(1).replace("&amp;", "&")
                return self._kcResolveUrl(base_url, action)

        # Fallback: any form with "authenticate" in action
        m = re.search(r'<form[^>]*action=[\x22\x27]([^\x22\x27]*authenticate[^\x22\x27]*)[\x22\x27]', html)
        if m:
            action = m.group(1).replace("&amp;", "&")
            return self._kcResolveUrl(base_url, action)

        return None

    def _kcGetPageId(self, html):
        """Extract data-page-id from body tag."""
        import re
        m = re.search(r'data-page-id=[\x22\x27]([^\x22\x27]+)[\x22\x27]', html)
        return m.group(1) if m else "unknown"

    def _kcHasField(self, html, field_name):
        """Check if an input field exists in the HTML."""
        import re
        return bool(re.search(r'name=[\x22\x27]%s[\x22\x27]' % re.escape(field_name), html))

    def _kcGetHiddenField(self, html, field_name):
        """Extract a hidden input field value."""
        import re
        m = re.search(
            r'<input[^>]*name=[\x22\x27]%s[\x22\x27][^>]*value=[\x22\x27]([^\x22\x27]*)[\x22\x27]' % re.escape(field_name), html)
        if not m:
            m = re.search(
                r'<input[^>]*value=[\x22\x27]([^\x22\x27]*)[\x22\x27][^>]*name=[\x22\x27]%s[\x22\x27]' % re.escape(field_name), html)
        return m.group(1) if m else ""

    def _generateTOTP(self, secret_base32, period=30, digits=6):
        """Generate a TOTP code from a base32 secret (RFC 6238)."""
        import time as _time
        import struct

        # Base32 decode
        secret_base32 = secret_base32.upper().replace(" ", "").replace("-", "")
        # Pad to multiple of 8
        padding = (8 - len(secret_base32) % 8) % 8
        secret_base32 += "=" * padding

        b32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        bits = ""
        for ch in secret_base32:
            if ch == "=":
                break
            idx = b32_alphabet.index(ch)
            bits += format(idx, '05b')

        key_bytes = bytearray()
        for i in range(0, len(bits) - 7, 8):
            key_bytes.append(int(bits[i:i+8], 2))

        # Time counter
        counter = int(_time.time()) // period
        msg = struct.pack(">Q", counter)

        # HMAC-SHA1 using Java crypto
        from javax.crypto import Mac as JMac
        from javax.crypto.spec import SecretKeySpec
        mac = JMac.getInstance("HmacSHA1")
        key_spec = SecretKeySpec(bytes(key_bytes), "HmacSHA1")
        mac.init(key_spec)
        hmac_result = mac.doFinal(msg)

        # Convert Java signed bytes to unsigned
        hmac_unsigned = [(b if b >= 0 else b + 256) for b in hmac_result]

        # Dynamic truncation (RFC 4226)
        offset = hmac_unsigned[-1] & 0x0F
        code = ((hmac_unsigned[offset] & 0x7F) << 24 |
                (hmac_unsigned[offset + 1] & 0xFF) << 16 |
                (hmac_unsigned[offset + 2] & 0xFF) << 8 |
                (hmac_unsigned[offset + 3] & 0xFF))

        otp = code % (10 ** digits)
        return str(otp).zfill(digits)

        # -- Keycloak helper methods --------------------------------------------

    def _kcRequest(self, method, url, body, content_type, cookie_jar):
        """Make an HTTP request via Burp, passing cookies from jar."""
        helpers = self._helpers
        url_obj = java.net.URL(url)
        host = url_obj.getHost()
        port = url_obj.getPort()
        use_https = url.startswith("https")
        if port == -1:
            port = 443 if use_https else 80

        path = url_obj.getPath() or "/"
        if url_obj.getQuery():
            path += "?" + url_obj.getQuery()

        headers = [
            "%s %s HTTP/1.1" % (method, path),
            "Host: %s" % host,
            "User-Agent: %s" % self._userAgentField.getText().strip(),
            "Accept: text/html,application/json,*/*",
        ]

        # Send cookies from jar
        if cookie_jar:
            cookie_str = "; ".join("%s=%s" % (k, v) for k, v in cookie_jar.items())
            headers.append("Cookie: %s" % cookie_str)

        body_bytes = None
        if body and content_type:
            headers.append("Content-Type: %s" % content_type)
            headers.append("Content-Length: %d" % len(body))
            body_bytes = helpers.stringToBytes(body)

        headers.append("Connection: close")
        request = helpers.buildHttpMessage(headers, body_bytes)
        http_service = helpers.buildHttpService(host, port, use_https)

        response = self._callbacks.makeHttpRequest(http_service, request)
        resp_bytes = response.getResponse()
        if resp_bytes is None:
            return (None, None)

        resp_info = helpers.analyzeResponse(resp_bytes)
        return (resp_bytes, resp_info.getHeaders())

    def _kcCollectCookies(self, resp_info, cookie_jar):
        """Extract Set-Cookie headers and add to cookie jar."""
        for header in resp_info.getHeaders():
            h = str(header)
            if h.lower().startswith("set-cookie:"):
                cookie_part = h.split(":", 1)[1].strip().split(";")[0].strip()
                if "=" in cookie_part:
                    name, val = cookie_part.split("=", 1)
                    cookie_jar[name.strip()] = val.strip()

    def _kcGetHeader(self, resp_info, name):
        """Get a response header value by name."""
        for header in resp_info.getHeaders():
            h = str(header)
            if h.lower().startswith(name.lower() + ":"):
                return h.split(":", 1)[1].strip()
        return None

    def _kcResolveUrl(self, base_url, relative):
        """Resolve a relative URL against a base URL."""
        if relative.startswith("http://") or relative.startswith("https://"):
            return relative
        base_obj = java.net.URL(base_url)
        resolved = java.net.URL(base_obj, relative)
        return str(resolved.toString())

    def _extractAuthValue(self, resp_bytes):
        """Extract auth value from a response based on current config."""
        helpers = self._helpers
        resp_info = helpers.analyzeResponse(resp_bytes)
        extract_mode = self._extractCombo.getSelectedItem()

        if extract_mode == "Set-Cookie header":
            cookies = []
            for header in resp_info.getHeaders():
                h = str(header)
                if h.lower().startswith("set-cookie:"):
                    cookie_val = h.split(":", 1)[1].strip().split(";")[0].strip()
                    cookies.append(cookie_val)
            if cookies:
                return "; ".join(cookies)

        elif extract_mode == "JSON body field":
            return self._extractJsonField(resp_bytes)

        return None

    def _extractJsonField(self, resp_bytes):
        """Extract a JSON field from response body."""
        helpers = self._helpers
        resp_info = helpers.analyzeResponse(resp_bytes)
        field_name = self._extractFieldName.getText().strip()
        if not field_name:
            return None
        body_offset = resp_info.getBodyOffset()
        body_str = helpers.bytesToString(resp_bytes[body_offset:])
        try:
            body_json = json.loads(body_str)
            parts = field_name.split(".")
            val = body_json
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    return None
            if val is not None:
                return str(val)
        except Exception:
            pass
        return None

    def _onRemoveJWT(self, event):
        row = self._jwtTable.getSelectedRow()
        if row >= 0:
            self._jwtModel.removeRow(row)
        else:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select a row to remove.", "Info",
                JOptionPane.INFORMATION_MESSAGE)

    def _collectAuthEntries(self):
        """Read the auth table and return list of (name, auth_type, value, login_body)."""
        if self._jwtTable.isEditing():
            self._jwtTable.getCellEditor().stopCellEditing()
        entries = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "").strip()
            auth_type = str(self._jwtModel.getValueAt(r, 1) or "Bearer").strip()
            value = str(self._jwtModel.getValueAt(r, 2) or "").strip()
            login_body = str(self._jwtModel.getValueAt(r, 3) or "").strip()
            if value or login_body:  # allow empty value if login_body exists (will refresh)
                if not name:
                    name = "ID-%d" % (r + 1)
                if auth_type not in ("Bearer", "Cookie"):
                    auth_type = "Bearer"
                entries.append((name, auth_type, value, login_body))
        return entries

    def _getBatchSize(self):
        """Read batch size field. Returns 0 for no limit."""
        try:
            val = int(self._batchSizeField.getText().strip())
            return max(0, val)
        except Exception:
            return 0

    def _resetPause(self):
        """Reset pause state for a new run."""
        self._requestCounter = 0
        self._pauseSemaphore.drainPermits()
        self._resumeBtn.setEnabled(False)

    def _onSend(self, event):
        idx = self._endpointCombo.getSelectedIndex()
        if idx < 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an endpoint first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        auth_entries = self._collectAuthEntries()
        if not auth_entries:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one auth identity.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        if self._paramTable.isEditing():
            self._paramTable.getCellEditor().stopCellEditing()

        _, method, path_template, _ = self._endpoints[idx]
        base = self._baseUrlField.getText().strip().rstrip("/")

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
        self._resetPause()
        batch_size = self._getBatchSize()
        self._statusLabel.setText("Sending %d request(s) (1 unauthenticated + %d with auth)..." % (len(auth_entries) + 1, len(auth_entries)))

        self._topTabs.setSelectedIndex(2)
        self._resultsTabbedPane.setSelectedIndex(0)

        runner = _RequestRunner(self, base, method, path_template, params, auth_entries,
                                self._userAgentField.getText().strip(), batch_size,
                                self._perRequestRefreshCb.isSelected(),
                                self._loginUrlField.getText().strip())
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
        if row < 0:
            return
        # Convert view row to model row (sorting may reorder)
        model_row = self._resultTable.convertRowIndexToModel(row)
        if 0 <= model_row < len(self._responses):
            self._currentRow = model_row

            # Show request in Burp editor
            try:
                raw_req = self._raw_requests[model_row] if model_row < len(self._raw_requests) else None
                if raw_req:
                    self._requestEditor.setMessage(raw_req, True)
                else:
                    self._requestEditor.setMessage([], True)
            except Exception:
                self._requestEditor.setMessage([], True)

            # Show response in Burp editor
            try:
                raw_resp = self._raw_responses[model_row] if model_row < len(self._raw_responses) else None
                if raw_resp:
                    self._responseEditor.setMessage(raw_resp, False)
                else:
                    self._responseEditor.setMessage([], False)
            except Exception:
                self._responseEditor.setMessage([], False)

    # -- Proxy history search -----------------------------------------------


    def _onAutoScan(self, event):
        """Scan every endpoint: auto-fill params from proxy, send all JWTs."""
        if not self._endpoints:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Load a Swagger file first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        # Stop editing so any in-progress cell value is committed
        auth_entries = self._collectAuthEntries()
        if not auth_entries:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one auth identity.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        confirm = JOptionPane.showConfirmDialog(self._mainPanel,
            "This will scan all %d endpoints with %d identity(ies) + unauthenticated.\n"
            "Total requests: %d\n\nContinue?" % (
                len(self._endpoints), len(auth_entries),
                len(self._endpoints) * (len(auth_entries) + 1)),
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
        self._pauseScanBtn.setEnabled(True)
        self._stopScanBtn.setEnabled(True)
        self._autoScanStopped = False
        self._autoScanPaused = False
        self._resetPause()
        batch_size = self._getBatchSize()
        self._statusLabel.setText("Auto Scan: starting %d endpoints..." % len(self._endpoints))

        # Switch to Requests tab > first auto-scan sub-tab
        self._topTabs.setSelectedIndex(2)
        if self._resultsTabbedPane.getTabCount() > 1:
            self._resultsTabbedPane.setSelectedIndex(1)

        runner = _AutoScanRunner(self, base, self._endpoints, auth_entries,
                                 self._userAgentField.getText().strip(), batch_size,
                                 self._autoRefreshCb.isSelected(),
                                 self._perRequestRefreshCb.isSelected(),
                                 self._loginUrlField.getText().strip())
        JThread(runner).start()

    def _createAutoScanTab(self, label, method="GET"):
        """Create a results tab for one endpoint and return its data dict."""
        is_mutating = method in ("POST", "PUT", "PATCH", "DELETE")
        bypass = self._bypassConfirmCb.isSelected()
        needs_confirm = is_mutating and not bypass

        resultCols = ["#", "Identity", "Status", "Size (bytes)", "Time (ms)"]
        model = DefaultTableModel(resultCols, 0)
        table = _EditableTable(model, [])
        table.getColumnModel().getColumn(0).setPreferredWidth(30)
        table.getColumnModel().getColumn(1).setPreferredWidth(200)
        table.getColumnModel().getColumn(2).setPreferredWidth(60)
        table.getColumnModel().getColumn(3).setPreferredWidth(80)
        table.getColumnModel().getColumn(4).setPreferredWidth(70)
        table.getColumnModel().getColumn(2).setCellRenderer(_StatusRenderer())
        sorter = TableRowSorter(model)
        table.setRowSorter(sorter)

        tab_data = {
            "model": model,
            "table": table,
            "responses": [],
            "requests": [],
            "raw_requests": [],
            "raw_responses": [],
            "http_services": [],
            "pending": needs_confirm,
            "method": method,
            "params": None,       # filled by auto scan runner
            "path_template": None, # filled by auto scan runner
        }

        # Click listener that updates the shared editors below
        table.addMouseListener(_AutoTabClickListener(self, tab_data))

        resultScroll = JScrollPane(table)

        # -- Editable params table + Resend button (common to all tabs) ---
        epParamCols = ["Name", "In", "Value"]
        epParamModel = DefaultTableModel(epParamCols, 0)
        epParamTable = _EditableTable(epParamModel, [2])
        epParamTable.getColumnModel().getColumn(0).setPreferredWidth(120)
        epParamTable.getColumnModel().getColumn(1).setPreferredWidth(50)
        epParamTable.getColumnModel().getColumn(2).setPreferredWidth(200)
        epParamTable.setRowSorter(TableRowSorter(epParamModel))

        tab_data["epParamModel"] = epParamModel
        tab_data["epParamTable"] = epParamTable

        epParamPanel = JPanel(BorderLayout(0, 2))
        epParamScroll = JScrollPane(epParamTable)
        epParamScroll.setBorder(BorderFactory.createTitledBorder(
            "Parameters (edit Value, then Resend)"))
        epParamPanel.add(epParamScroll, BorderLayout.CENTER)

        resendRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        resendBtn = JButton("Resend All Identities")
        resendBtn.setToolTipText("Clear results and resend with current param values for all auth identities")
        resendBtn.addActionListener(
            lambda e, td=tab_data: self._onResendEndpoint(td))
        resendRow.add(resendBtn)
        epParamPanel.add(resendRow, BorderLayout.SOUTH)

        # -- Split: params (top) + results (bottom) -----------------------
        paramResultSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        paramResultSplit.setResizeWeight(0.30)
        paramResultSplit.setDividerSize(8)
        paramResultSplit.setContinuousLayout(True)
        epParamPanel.setMinimumSize(Dimension(100, 60))
        resultScroll.setMinimumSize(Dimension(100, 60))
        paramResultSplit.setTopComponent(epParamPanel)
        paramResultSplit.setBottomComponent(resultScroll)

        if needs_confirm:
            # Wrap in a panel with a confirm banner + preview + results
            tabPanel = JPanel(BorderLayout(0, 4))

            # -- Confirm banner -------------------------------------------
            bannerPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
            bannerPanel.setBorder(BorderFactory.createLineBorder(Color(200, 120, 0), 2))
            bannerPanel.setBackground(Color(255, 245, 220))

            warnLabel = JLabel("  %s request -- review preview below, then confirm  " % method)
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

            # -- Preview area ---------------------------------------------
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

            # -- Layout: banner on top, preview + results in a split ------
            previewResultSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            previewResultSplit.setResizeWeight(0.4)
            previewResultSplit.setDividerSize(8)
            previewResultSplit.setContinuousLayout(True)
            previewScroll.setMinimumSize(Dimension(100, 40))
            paramResultSplit.setMinimumSize(Dimension(100, 60))
            previewResultSplit.setTopComponent(previewScroll)
            previewResultSplit.setBottomComponent(paramResultSplit)
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
            tabContent = paramResultSplit

        # Truncate label for tab title
        short_label = label if len(label) <= 35 else label[:32] + "..."
        self._resultsTabbedPane.addTab(short_label, tabContent)
        idx = self._resultsTabbedPane.getTabCount() - 1
        self._resultsTabbedPane.setToolTipTextAt(idx, label)

        # Custom tab header with close button
        tabHeader = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
        tabHeader.setOpaque(False)
        tabLabel = JLabel(short_label)
        tabHeader.add(tabLabel)
        closeBtn = JButton("x")
        closeBtn.setPreferredSize(Dimension(18, 18))
        closeBtn.setMargin(Insets(0, 0, 0, 0))
        closeBtn.setFont(closeBtn.getFont().deriveFont(Font.PLAIN, 10.0))
        closeBtn.setToolTipText("Close this tab")
        closeBtn.setBorderPainted(False)
        closeBtn.setContentAreaFilled(False)
        closeBtn.addActionListener(
            lambda e, tc=tabContent: self._closeAutoScanTab(tc))
        tabHeader.add(closeBtn)
        self._resultsTabbedPane.setTabComponentAt(idx, tabHeader)

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

        auth_entries = self._collectAuthEntries()

        base = self._baseUrlField.getText().strip().rstrip("/")

        # Send in background
        runner = _PendingEndpointRunner(
            self, tab_data, base, auth_entries, bannerPanel,
            self._userAgentField.getText().strip(),
            self._perRequestRefreshCb.isSelected(),
            self._loginUrlField.getText().strip())
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

    def _closeAutoScanTab(self, tabContent):
        """Close an auto-scan tab by its content component."""
        idx = self._resultsTabbedPane.indexOfComponent(tabContent)
        if idx > 0:  # never close tab 0 (Manual)
            self._resultsTabbedPane.removeTabAt(idx)

    def _onResendEndpoint(self, tab_data):
        """Re-read params from the per-endpoint table and resend all requests."""
        # Stop editing
        epTable = tab_data.get("epParamTable")
        if epTable and epTable.isEditing():
            epTable.getCellEditor().stopCellEditing()

        # Read current param values from the editable table
        epModel = tab_data.get("epParamModel")
        if not epModel:
            return
        params = []
        for r in range(epModel.getRowCount()):
            params.append({
                "name": str(epModel.getValueAt(r, 0) or ""),
                "in": str(epModel.getValueAt(r, 1) or ""),
                "value": str(epModel.getValueAt(r, 2) or ""),
            })
        tab_data["params"] = params

        method = tab_data.get("method", "GET")
        path_template = tab_data.get("path_template", "/")

        # Clear previous results
        tab_data["model"].setRowCount(0)
        tab_data["raw_requests"] = []
        tab_data["raw_responses"] = []
        tab_data["http_services"] = []

        # Collect auth entries
        auth_entries = self._collectAuthEntries()
        if not auth_entries:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one auth identity.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        base = self._baseUrlField.getText().strip().rstrip("/")
        ua = self._userAgentField.getText().strip()

        self._statusLabel.setText("Resending %s %s with %d identities..." % (
            method, path_template, len(auth_entries) + 1))

        runner = _ResendEndpointRunner(self, tab_data, base, auth_entries, ua,
                                       method, path_template, params,
                                       self._perRequestRefreshCb.isSelected(),
                                       self._loginUrlField.getText().strip())
        JThread(runner).start()

    def _onAutoTabClick(self, tab_data, row):
        """Handle click on a row in an auto-scan tab -- update shared editors."""
        # Convert view row to model row (sorting may reorder)
        table = tab_data["table"]
        model_row = table.convertRowIndexToModel(row)
        if 0 <= model_row < len(tab_data["raw_requests"]):
            # Point IMessageEditorController to this tab's data
            self._raw_requests = tab_data["raw_requests"]
            self._raw_responses = tab_data["raw_responses"]
            self._http_services = tab_data["http_services"]
            self._currentRow = model_row

            try:
                raw_req = tab_data["raw_requests"][model_row]
                if raw_req:
                    self._requestEditor.setMessage(raw_req, True)
                else:
                    self._requestEditor.setMessage([], True)
            except Exception:
                self._requestEditor.setMessage([], True)

            try:
                raw_resp = tab_data["raw_responses"][model_row]
                if raw_resp:
                    self._responseEditor.setMessage(raw_resp, False)
                else:
                    self._responseEditor.setMessage([], False)
            except Exception:
                self._responseEditor.setMessage([], False)

    # -- Global Parameters tab ---------------------------------------------

    def _populateGlobalParams(self):
        """Extract all unique params from swagger and populate the global table."""
        self._globalParamModel.setRowCount(0)
        self._globalProxyModel.setRowCount(0)
        self._globalParams = {}
        seen = {}  # {param_name: {in_types, endpoints, required, types}}

        for label, method, path_template, param_defs in self._endpoints:
            for p in param_defs:
                name = p["name"]
                if name not in seen:
                    seen[name] = {"in_types": set(), "endpoints": [], "required": False, "types": set()}
                seen[name]["in_types"].add(p["in"])
                if p.get("required"):
                    seen[name]["required"] = True
                ptype = p.get("type", "string")
                if ptype:
                    seen[name]["types"].add(ptype)
                short = label if len(label) <= 25 else label[:22] + "..."
                if short not in seen[name]["endpoints"]:
                    seen[name]["endpoints"].append(short)

        # Collect all unique types for the combo box
        all_types = set()
        for info in seen.values():
            all_types.update(info["types"])

        for name in sorted(seen.keys()):
            info = seen[name]
            in_types = ", ".join(sorted(info["in_types"]))
            param_types = ", ".join(sorted(info["types"])) if info["types"] else "string"
            required = "True" if info["required"] else "False"
            ep_count = len(info["endpoints"])
            ep_str = "%d endpoint(s)" % ep_count
            self._globalParamModel.addRow([name, in_types, param_types, required, ep_str, "0", ""])

        # Update bulk type combo with discovered types
        self._bulkTypeCombo.removeAllItems()
        for t in sorted(all_types):
            self._bulkTypeCombo.addItem(t)
        if not all_types:
            self._bulkTypeCombo.addItem("string")

        self._statusLabel.setText("Parameters tab: %d unique parameters, types: %s" % (
            len(seen), ", ".join(sorted(all_types))))

    def _onAutoFillGlobalParams(self, event):
        """Scan proxy history and fill the Value column with first match."""
        if self._globalParamModel.getRowCount() == 0:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Load a Swagger file first.", "Warning",
                JOptionPane.WARNING_MESSAGE)
            return

        self._autoFillBtn.setEnabled(False)
        self._statusLabel.setText("Scanning proxy history for parameter values...")

        # Collect all param names we need
        param_names = set()
        for r in range(self._globalParamModel.getRowCount()):
            param_names.add(str(self._globalParamModel.getValueAt(r, 0)))

        runner = _GlobalParamFillRunner(self, param_names)
        JThread(runner).start()

    def _onGlobalParamFillDone(self, cache, all_values):
        """Called when proxy scan completes. cache={name:first_val}, all_values={name:[(val,url,src),...]}"""
        self._globalProxyCache = all_values  # store for click lookup
        filled = 0
        for r in range(self._globalParamModel.getRowCount()):
            name = str(self._globalParamModel.getValueAt(r, 0))
            # Update Found count
            found_count = len(all_values.get(name, []))
            self._globalParamModel.setValueAt(str(found_count), r, 5)
            # Auto-fill Value if empty
            current = str(self._globalParamModel.getValueAt(r, 6) or "")
            if not current and name in cache:
                self._globalParamModel.setValueAt(cache[name], r, 6)
                filled += 1
        self._autoFillBtn.setEnabled(True)
        total_values = sum(len(v) for v in all_values.values())
        self._statusLabel.setText("Auto-fill: %d/%d params filled. %d total values found across %d params." % (
            filled, self._globalParamModel.getRowCount(), total_values, len(all_values)))
        # Auto-show values for the first param with results
        if self._globalParamTable.getRowCount() > 0:
            self._globalParamTable.setRowSelectionInterval(0, 0)
            self._onGlobalParamClick(0)

    def _onApplyGlobalParams(self, event):
        """Copy values from global params table into _globalParams dict and per-endpoint tables."""
        if self._globalParamTable.isEditing():
            self._globalParamTable.getCellEditor().stopCellEditing()

        self._globalParams = {}
        applied = 0
        for r in range(self._globalParamModel.getRowCount()):
            name = str(self._globalParamModel.getValueAt(r, 0))
            value = str(self._globalParamModel.getValueAt(r, 6) or "")
            if value:
                self._globalParams[name] = value
                applied += 1

        # Also update the per-endpoint param table if it's visible
        for r in range(self._paramModel.getRowCount()):
            pname = str(self._paramModel.getValueAt(r, 0))
            if pname in self._globalParams:
                self._paramModel.setValueAt(self._globalParams[pname], r, 4)

        self._statusLabel.setText("Applied %d global parameter values." % applied)

    def _onBulkFillByType(self, event):
        """Fill placeholder values for parameters matching the selected type."""
        target_type = str(self._bulkTypeCombo.getSelectedItem() or "").strip().lower()
        fill_value = self._bulkValueField.getText().strip()
        replace_existing = self._bulkReplaceExistingCb.isSelected()
        include_optional = self._bulkIncludeOptionalCb.isSelected()

        if not target_type:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select a type first.", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        if not fill_value:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Enter a value to fill.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        if self._globalParamTable.isEditing():
            self._globalParamTable.getCellEditor().stopCellEditing()

        filled = 0
        skipped = 0
        for r in range(self._globalParamModel.getRowCount()):
            param_type = str(self._globalParamModel.getValueAt(r, 2) or "").strip().lower()
            required = str(self._globalParamModel.getValueAt(r, 3) or "").strip()
            current_value = str(self._globalParamModel.getValueAt(r, 6) or "").strip()

            # Check type match (support comma-separated types like "string, integer")
            type_matches = target_type in param_type

            if not type_matches:
                continue

            # Check required/optional filter
            is_required = required == "True"
            if not include_optional and not is_required:
                skipped += 1
                continue

            # Check if we should skip already-populated values
            if current_value and not replace_existing:
                skipped += 1
                continue

            # Apply the value
            self._globalParamModel.setValueAt(fill_value, r, 6)
            filled += 1

        self._statusLabel.setText(
            "Bulk fill '%s' for type '%s': %d filled, %d skipped." % (
                fill_value, target_type, filled, skipped))

    def _onLoadBulkDictionary(self, event):
        """Load a JSON dictionary file mapping types to placeholder values and apply all at once.
        File format: {"string": "test", "integer": "1", "number": "0.5", "boolean": "true"}
        """
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Type Dictionary (JSON)")
        chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
        if chooser.showOpenDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            with open(path, "r") as f:
                raw = f.read()
            dictionary = json.loads(raw)
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Failed to parse dictionary file:\n%s\n\n"
                "Expected format:\n"
                '{"string": "test", "integer": "1", "boolean": "true"}' % str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
            return

        if not isinstance(dictionary, dict):
            JOptionPane.showMessageDialog(self._mainPanel,
                "Dictionary must be a JSON object mapping types to values.",
                "Error", JOptionPane.ERROR_MESSAGE)
            return

        if self._globalParamTable.isEditing():
            self._globalParamTable.getCellEditor().stopCellEditing()

        replace_existing = self._bulkReplaceExistingCb.isSelected()
        include_optional = self._bulkIncludeOptionalCb.isSelected()

        total_filled = 0
        total_skipped = 0
        types_applied = []

        for target_type, fill_value in dictionary.items():
            target_lower = str(target_type).strip().lower()
            fill_str = str(fill_value).strip()
            if not target_lower or not fill_str:
                continue

            filled = 0
            for r in range(self._globalParamModel.getRowCount()):
                param_type = str(self._globalParamModel.getValueAt(r, 2) or "").strip().lower()
                required = str(self._globalParamModel.getValueAt(r, 3) or "").strip()
                current_value = str(self._globalParamModel.getValueAt(r, 6) or "").strip()

                if target_lower not in param_type:
                    continue

                is_required = required == "True"
                if not include_optional and not is_required:
                    total_skipped += 1
                    continue

                if current_value and not replace_existing:
                    total_skipped += 1
                    continue

                self._globalParamModel.setValueAt(fill_str, r, 6)
                filled += 1

            if filled > 0:
                types_applied.append("%s->%s (%d)" % (target_lower, fill_str, filled))
            total_filled += filled

        self._statusLabel.setText(
            "Dictionary applied: %d params filled, %d skipped. [%s]" % (
                total_filled, total_skipped, ", ".join(types_applied) if types_applied else "no matches"))

    def _onLoadWordlist(self, event):
        """Load a text file with one value per line as a fuzzing wordlist."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Wordlist (one value per line)")
        if chooser.showOpenDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            with open(path, "r") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self._wordlist = lines
            self._fuzzTargetType = str(self._bulkTypeCombo.getSelectedItem() or "string").strip().lower()
            self._wordlistLabel.setText("  %d words loaded (type: %s)  " % (len(lines), self._fuzzTargetType))
            self._fuzzScanBtn.setEnabled(len(lines) > 0 and len(self._endpoints) > 0)
            self._statusLabel.setText("Wordlist loaded: %d values from %s (target type: %s)" % (
                len(lines), path, self._fuzzTargetType))
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Failed to load wordlist:\n%s" % str(e),
                "Error", JOptionPane.ERROR_MESSAGE)

    def _onFuzzScan(self, event):
        """Launch a fuzz scan: for each endpoint x each word x each identity."""
        if not self._wordlist:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Load a wordlist first.", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        if not self._endpoints:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Load a Swagger file first.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        auth_entries = self._collectAuthEntries()
        if not auth_entries:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Add at least one auth identity.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        fuzz_type = self._fuzzTargetType
        n_words = len(self._wordlist)
        n_eps = len(self._endpoints)
        n_ids = len(auth_entries) + 1  # +1 for no-auth
        total = n_eps * n_words * n_ids

        confirm = JOptionPane.showConfirmDialog(self._mainPanel,
            "Fuzz scan: %d endpoints x %d words x %d identities = %d requests\n"
            "Target type: %s\n\nContinue?" % (n_eps, n_words, n_ids, total, fuzz_type),
            "Confirm Fuzz Scan", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return

        base = self._baseUrlField.getText().strip().rstrip("/")

        # Remove previous auto-scan tabs
        while self._resultsTabbedPane.getTabCount() > 1:
            self._resultsTabbedPane.removeTabAt(self._resultsTabbedPane.getTabCount() - 1)
        self._autoScanTabs = []

        # Create one tab per endpoint
        for idx, (label, method, path_template, params) in enumerate(self._endpoints):
            tab_data = self._createAutoScanTab(label, method)
            self._autoScanTabs.append(tab_data)

        self._autoScanBtn.setEnabled(False)
        self._fuzzScanBtn.setEnabled(False)
        self._sendBtn.setEnabled(False)
        self._pauseScanBtn.setEnabled(True)
        self._stopScanBtn.setEnabled(True)
        self._autoScanStopped = False
        self._autoScanPaused = False
        self._resetPause()
        batch_size = self._getBatchSize()

        self._topTabs.setSelectedIndex(2)
        if self._resultsTabbedPane.getTabCount() > 1:
            self._resultsTabbedPane.setSelectedIndex(1)

        self._statusLabel.setText("Fuzz scan: %d endpoints x %d words..." % (n_eps, n_words))

        runner = _FuzzScanRunner(self, base, self._endpoints, auth_entries,
                                 self._wordlist, fuzz_type,
                                 self._userAgentField.getText().strip(),
                                 batch_size,
                                 self._perRequestRefreshCb.isSelected(),
                                 self._loginUrlField.getText().strip())
        JThread(runner).start()

    def _onGlobalParamClick(self, row):
        """Show all proxy values for the selected parameter."""
        self._globalProxyModel.setRowCount(0)
        if row < 0:
            return
        # Convert view row to model row (sorting may reorder)
        model_row = self._globalParamTable.convertRowIndexToModel(row)
        name = str(self._globalParamModel.getValueAt(model_row, 0))
        cache = getattr(self, '_globalProxyCache', {})
        values = cache.get(name, [])
        for val, url, src in values:
            self._globalProxyModel.addRow([val, url, src])
        if not values:
            self._globalProxyModel.addRow(["(no values found in proxy)", "", ""])

    def _onGlobalProxyValDoubleClick(self, row):
        """Use a proxy value: set it in the global param table."""
        if row < 0:
            return
        model_row = self._globalProxyTable.convertRowIndexToModel(row)
        value = str(self._globalProxyModel.getValueAt(model_row, 0))
        # Find which global param row is selected
        sel = self._globalParamTable.getSelectedRow()
        if sel >= 0:
            sel_model = self._globalParamTable.convertRowIndexToModel(sel)
            self._globalParamModel.setValueAt(value, sel_model, 6)

    # -- State save / load --------------------------------------------------

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
        state["batch_size"] = self._batchSizeField.getText()
        state["bypass_confirm"] = self._bypassConfirmCb.isSelected()

        # Global parameter values
        gp = {}
        for r in range(self._globalParamModel.getRowCount()):
            name = str(self._globalParamModel.getValueAt(r, 0))
            val = str(self._globalParamModel.getValueAt(r, 6) or "")
            if val:
                gp[name] = val
        state["global_params"] = gp
        state["selected_endpoint"] = self._endpointCombo.getSelectedIndex()

        # Parameter values keyed by name (so they survive endpoint reloads)
        param_values = {}
        for r in range(self._paramModel.getRowCount()):
            name = str(self._paramModel.getValueAt(r, 0))
            val = str(self._paramModel.getValueAt(r, 4) or "")
            if val:
                param_values[name] = val
        state["param_values"] = param_values

        # Auth identities (with login body)
        auth_entries = []
        for r in range(self._jwtModel.getRowCount()):
            name = str(self._jwtModel.getValueAt(r, 0) or "")
            auth_type = str(self._jwtModel.getValueAt(r, 1) or "Bearer")
            value = str(self._jwtModel.getValueAt(r, 2) or "")
            login_body = str(self._jwtModel.getValueAt(r, 3) or "")
            auth_entries.append({"name": name, "type": auth_type, "value": value, "login_body": login_body})
        state["auth_entries"] = auth_entries

        # Session refresh config
        state["login_mode"] = self._loginModeCombo.getSelectedItem()
        state["login_url"] = self._loginUrlField.getText()
        state["extract_mode"] = self._extractCombo.getSelectedItem()
        state["extract_field"] = self._extractFieldName.getText()
        state["auto_refresh"] = self._autoRefreshCb.isSelected()
        state["per_request_refresh"] = self._perRequestRefreshCb.isSelected()

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

        # 2c. Batch size
        batch_size = state.get("batch_size", "")
        if batch_size:
            self._batchSizeField.setText(batch_size)

        # 2d. Bypass confirm
        if state.get("bypass_confirm", False):
            self._bypassConfirmCb.setSelected(True)

        # 2e. Global parameter values
        gp = state.get("global_params", {})
        if gp:
            self._globalParams = gp
            for r in range(self._globalParamModel.getRowCount()):
                name = str(self._globalParamModel.getValueAt(r, 0))
                if name in gp:
                    self._globalParamModel.setValueAt(gp[name], r, 6)

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

        # 5. Auth identities
        self._jwtModel.setRowCount(0)
        auth_entries = state.get("auth_entries", [])
        for entry in auth_entries:
            name = entry.get("name", "")
            auth_type = entry.get("type", "Bearer")
            value = entry.get("value", "")
            login_body = entry.get("login_body", "")
            self._jwtModel.addRow([name, auth_type, value, login_body])

        # Backward compat: old state files with jwt_pairs or jwts
        if not auth_entries:
            jwt_pairs = state.get("jwt_pairs", [])
            for pair in jwt_pairs:
                self._jwtModel.addRow([pair.get("name", ""), "Bearer", pair.get("token", ""), ""])
            if not jwt_pairs:
                for i, token in enumerate(state.get("jwts", [])):
                    self._jwtModel.addRow(["ID-%d" % (i + 1), "Bearer", token, ""])

        # 5b. Session refresh config
        login_mode = state.get("login_mode", "")
        if login_mode:
            self._loginModeCombo.setSelectedItem(login_mode)
        login_url = state.get("login_url", "")
        if login_url:
            self._loginUrlField.setText(login_url)
        extract_mode = state.get("extract_mode", "")
        if extract_mode:
            self._extractCombo.setSelectedItem(extract_mode)
        extract_field = state.get("extract_field", "")
        if extract_field:
            self._extractFieldName.setText(extract_field)
        if state.get("auto_refresh", False):
            self._autoRefreshCb.setSelected(True)
        if state.get("per_request_refresh", False):
            self._perRequestRefreshCb.setSelected(True)

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


# -- Mouse listener for proxy values table ----------------------------------

# -- Mouse listener for global params table ---------------------------------

# -- Session refresh runner -------------------------------------------------

class _SessionRefreshRunner(Runnable):
    """Refreshes auth values for all identities by calling the login macro."""

    def __init__(self, extender, login_url):
        self._ext = extender
        self._login_url = login_url

    def run(self):
        model = self._ext._jwtModel
        refreshed = 0
        errors = 0

        for r in range(model.getRowCount()):
            name = str(model.getValueAt(r, 0) or "")
            auth_type = str(model.getValueAt(r, 1) or "Bearer")
            login_body = str(model.getValueAt(r, 3) or "").strip()

            if not login_body:
                continue

            self._ext._callbacks.printOutput(
                "[SessionRefresh] Refreshing '%s'..." % name)

            new_value = self._ext._doRefreshSession(
                self._login_url, login_body, auth_type)

            if new_value:
                cur_row = r

                class _Update(Runnable):
                    def __init__(s):
                        s.r = cur_row; s.v = new_value
                    def run(s):
                        model.setValueAt(s.v, s.r, 2)

                SwingUtilities.invokeLater(_Update())
                refreshed += 1
                self._ext._callbacks.printOutput(
                    "[SessionRefresh] '%s' refreshed: %s" % (
                        name, new_value[:50] + "..." if len(new_value) > 50 else new_value))
            else:
                errors += 1
                self._ext._callbacks.printOutput(
                    "[SessionRefresh] '%s' FAILED -- no value extracted" % name)

        class _Done(Runnable):
            def run(s):
                self._ext._refreshAllBtn.setEnabled(True)
                self._ext._statusLabel.setText(
                    "Session refresh: %d refreshed, %d failed, %d skipped (no login body)." % (
                        refreshed, errors,
                        model.getRowCount() - refreshed - errors))
        SwingUtilities.invokeLater(_Done())


# -- Mouse listener for global params table ---------------------------------

class _GlobalParamClickListener(MouseAdapter):
    def __init__(self, extender):
        self._ext = extender

    def mouseClicked(self, event):
        row = self._ext._globalParamTable.getSelectedRow()
        if row >= 0:
            self._ext._onGlobalParamClick(row)


class _GlobalProxyValClickListener(MouseAdapter):
    def __init__(self, extender):
        self._ext = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            row = self._ext._globalProxyTable.getSelectedRow()
            if row >= 0:
                self._ext._onGlobalProxyValDoubleClick(row)


# -- Global param proxy fill runner -----------------------------------------

class _GlobalParamFillRunner(Runnable):
    """Scans proxy history and collects ALL values for each param name."""

    def __init__(self, extender, param_names):
        self._ext = extender
        self._param_names = param_names

    def run(self):
        helpers = self._ext._helpers
        cache = {}       # {name: first_value}
        all_values = {}  # {name: [(value, url, source), ...]}
        seen = {}        # {(name, value): True} for dedup

        try:
            history = self._ext._callbacks.getProxyHistory()
            for item in history:
                try:
                    req_bytes = item.getRequest()
                    if req_bytes is None:
                        continue

                    http_svc = item.getHttpService()
                    if http_svc:
                        req_info = helpers.analyzeRequest(http_svc, req_bytes)
                    else:
                        req_info = helpers.analyzeRequest(req_bytes)

                    url = str(req_info.getUrl())
                    method = str(req_info.getMethod())
                    display_url = url if len(url) <= 60 else url[:57] + "..."

                    # Request params
                    for param in req_info.getParameters():
                        pname = str(param.getName())
                        pval = str(param.getValue())
                        try:
                            pval = helpers.urlDecode(pval)
                        except Exception:
                            pass
                        if pname in self._param_names and pval:
                            if pname not in cache:
                                cache[pname] = pval
                            key = (pname, pval)
                            if key not in seen:
                                seen[key] = True
                                all_values.setdefault(pname, []).append(
                                    (pval, display_url, "%s request" % method))

                    # Request JSON body
                    req_bo = req_info.getBodyOffset()
                    if req_bo < len(req_bytes):
                        body_str = helpers.bytesToString(req_bytes[req_bo:])
                        if body_str and body_str.strip().startswith("{"):
                            try:
                                self._scan_json(json.loads(body_str), display_url,
                                    "%s req body" % method, cache, all_values, seen)
                            except Exception:
                                pass

                    # Response JSON body
                    resp_bytes = item.getResponse()
                    if resp_bytes:
                        try:
                            resp_info = helpers.analyzeResponse(resp_bytes)
                            resp_bo = resp_info.getBodyOffset()
                            if resp_bo < len(resp_bytes):
                                resp_str = helpers.bytesToString(resp_bytes[resp_bo:])
                                if resp_str and resp_str.strip()[:1] in ("{", "["):
                                    try:
                                        self._scan_json(json.loads(resp_str), display_url,
                                            "%s response" % method, cache, all_values, seen)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        class _Done(Runnable):
            def __init__(s):
                s.c = cache; s.a = all_values
            def run(s):
                self._ext._onGlobalParamFillDone(s.c, s.a)
        SwingUtilities.invokeLater(_Done())

    def _scan_json(self, obj, url, src, cache, all_values, seen):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in self._param_names and val is not None:
                    str_val = str(val)
                    if str_val:
                        if key not in cache:
                            cache[key] = str_val
                        k = (key, str_val)
                        if k not in seen:
                            seen[k] = True
                            all_values.setdefault(key, []).append((str_val, url, src))
                if isinstance(val, dict):
                    self._scan_json(val, url, src, cache, all_values, seen)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            self._scan_json(item, url, src, cache, all_values, seen)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._scan_json(item, url, src, cache, all_values, seen)


# -- Mouse listener for result table ----------------------------------------

class _ResultClickListener(MouseAdapter):
    def __init__(self, extender):
        self._ext = extender

    def mouseClicked(self, event):
        row = self._ext._resultTable.getSelectedRow()
        if row >= 0:
            self._ext._onResultClick(row)


# -- Mouse listener for auto-scan tab tables --------------------------------

class _AutoTabClickListener(MouseAdapter):
    def __init__(self, extender, tab_data):
        self._ext = extender
        self._tab_data = tab_data

    def mouseClicked(self, event):
        row = self._tab_data["table"].getSelectedRow()
        if row >= 0:
            self._ext._onAutoTabClick(self._tab_data, row)


# -- Auto Scan runner -------------------------------------------------------

class _AutoScanRunner(Runnable):
    """Iterates all endpoints, auto-fills params from proxy, sends requests."""

    def __init__(self, extender, base, endpoints, auth_entries, user_agent="Swagger_Tester/1.0", batch_size=0, auto_refresh=False, per_request_refresh=False, login_url=""):
        self._ext = extender
        self._base = base
        self._endpoints = endpoints
        self._auth_entries = auth_entries  # list of (name, type, value, login_body)
        self._user_agent = user_agent
        self._batch_size = batch_size
        self._auto_refresh = auto_refresh
        self._per_request_refresh = per_request_refresh
        self._login_url = login_url

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[AutoScan] %s" % msg)
        except Exception:
            pass

    def run(self):
        import time
        helpers = self._ext._helpers
        total_ep = len(self._endpoints)

        # -- Auto-refresh sessions if enabled -----------------------------
        if self._auto_refresh:
            self._log("Auto-refreshing sessions before scan...")
            login_url = self._login_url or self._ext._loginUrlField.getText().strip()
            if login_url:
                model = self._ext._jwtModel
                for r in range(model.getRowCount()):
                    name = str(model.getValueAt(r, 0) or "")
                    auth_type = str(model.getValueAt(r, 1) or "Bearer")
                    login_body = str(model.getValueAt(r, 3) or "").strip()
                    if login_body:
                        new_val = self._ext._doRefreshSession(login_url, login_body, auth_type)
                        if new_val:
                            cur_row = r
                            class _Upd(Runnable):
                                def __init__(s):
                                    s.r = cur_row; s.v = new_val
                                def run(s):
                                    model.setValueAt(s.v, s.r, 2)
                            SwingUtilities.invokeLater(_Upd())
                            self._log("  Refreshed '%s'" % name)
                            # Update auth_entries too (4-tuple)
                            for i, (n, t, v, lb) in enumerate(self._auth_entries):
                                if n == name:
                                    self._auth_entries[i] = (n, t, new_val, lb)

        # -- Pre-build proxy param cache (search once, reuse for all) -----
        self._log("Building proxy parameter cache...")
        proxy_cache = {}  # {param_name: first_value_found}
        items_scanned = 0
        try:
            history = self._ext._callbacks.getProxyHistory()
            self._log("Proxy history has %d items" % len(history))
            for item in history:
                try:
                    req_bytes = item.getRequest()
                    if req_bytes is None:
                        continue
                    items_scanned += 1
                    http_svc = item.getHttpService()

                    # Use simpler analyzeRequest(byte[]) if service is null
                    if http_svc:
                        req_info = helpers.analyzeRequest(http_svc, req_bytes)
                    else:
                        req_info = helpers.analyzeRequest(req_bytes)

                    # Request params (Burp returns URL-encoded values)
                    for param in req_info.getParameters():
                        pname = str(param.getName())
                        pval = str(param.getValue())
                        # URL-decode the value
                        try:
                            pval = helpers.urlDecode(pval)
                        except Exception:
                            pass
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
                        try:
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
                            pass
                except Exception as e:
                    continue
        except Exception as e:
            self._log("Proxy cache error: %s" % str(e))

        self._log("Proxy cache: scanned %d items, found %d unique param names." % (
            items_scanned, len(proxy_cache)))
        if proxy_cache:
            sample = list(proxy_cache.items())[:10]
            for k, v in sample:
                vshort = v[:40] + "..." if len(v) > 40 else v
                self._log("  cache: %s = %s" % (k, vshort))

        # -- Process each endpoint ----------------------------------------
        for ep_idx, (label, method, path_template, param_defs) in enumerate(self._endpoints):
            # Check stop flag
            if self._ext._autoScanStopped:
                self._log("Auto scan stopped by user at endpoint %d/%d" % (ep_idx + 1, total_ep))
                break

            # Check pause flag
            while self._ext._autoScanPaused and not self._ext._autoScanStopped:
                import time
                time.sleep(0.3)
            if self._ext._autoScanStopped:
                break

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

            # Auto-fill params: global params > proxy cache > swagger default > param name
            params = []
            filled = 0
            global_params = self._ext._globalParams
            for p in param_defs:
                value = global_params.get(p["name"], "")
                if not value:
                    value = proxy_cache.get(p["name"], "")
                if not value and p.get("default"):
                    value = str(p["default"])
                # For required params with no value found, use the param name
                if not value and p.get("required"):
                    value = p["name"]
                if value and value != p["name"]:
                    filled += 1
                params.append({
                    "name": p["name"],
                    "in": p["in"],
                    "value": value,
                })
            self._log("  -> %d/%d params auto-filled (global + proxy)" % (filled, len(param_defs)))

            # Store params in tab_data for potential deferred sending
            tab_data["params"] = params
            tab_data["path_template"] = path_template

            # Populate the per-endpoint editable params table
            class _FillParamTable(Runnable):
                def __init__(s):
                    s.td = tab_data; s.p = params
                def run(s):
                    m = s.td.get("epParamModel")
                    if m:
                        m.setRowCount(0)
                        for pp in s.p:
                            m.addRow([pp["name"], pp["in"], pp["value"]])
            SwingUtilities.invokeLater(_FillParamTable())

            # Skip mutating methods -- user must confirm via the banner button
            if tab_data.get("pending"):
                self._log("[%d/%d] PENDING (mutating %s) -- waiting for confirm" % (
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

            # -- Send unauthenticated request -----------------------------
            row_num = 0
            row_num += 1
            self._sendOne(tab_data, row_num, "<No Auth>", None, None, "",
                          method, path_template, params)

            # -- Send one request per auth identity ------------------------
            for auth_name, auth_type, auth_value, auth_login_body in self._auth_entries:
                row_num += 1
                self._sendOne(tab_data, row_num, auth_name, auth_type,
                              auth_value, auth_login_body, method, path_template, params)

        # -- Done ---------------------------------------------------------
        class _Done(Runnable):
            def run(s):
                self._ext._autoScanBtn.setEnabled(True)
                self._ext._sendBtn.setEnabled(True)
                self._ext._pauseScanBtn.setEnabled(False)
                self._ext._stopScanBtn.setEnabled(False)
                self._ext._resumeBtn.setEnabled(False)
                if self._ext._autoScanStopped:
                    self._ext._statusLabel.setText(
                        "Auto Scan stopped by user after %d/%d endpoints." % (ep_idx + 1, total_ep))
                else:
                    self._ext._statusLabel.setText(
                        "Auto Scan complete -- %d endpoints, %d requests each." % (
                            total_ep, len(self._auth_entries) + 1))
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
        lines.append("Authorization/Cookie: <each identity will be inserted>")
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
        lines.append("== WILL SEND %d REQUEST(S) ==" % (len(self._auth_entries) + 1))
        lines.append("")
        lines.append("  1. <No Auth>  (no auth header)")
        for i, (name, atype, _) in enumerate(self._auth_entries):
            lines.append("  %d. %s  [%s]" % (i + 2, name, atype))

        return "\n".join(lines)

    def _sendOne(self, tab_data, row_num, identity, auth_type, auth_value, login_body, method, path_template, params):
        """Send a single request and add the result to tab_data."""
        if self._ext._autoScanStopped:
            return
        # Per-request refresh if enabled
        if self._per_request_refresh and login_body and self._login_url:
            refreshed = self._ext._doRefreshSession(self._login_url, login_body, auth_type)
            if refreshed:
                auth_value = refreshed
                self._log("  Refreshed '%s' before request" % identity)
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
            if auth_value and auth_type == "Bearer":
                headers.append("Authorization: Bearer %s" % auth_value)
            elif auth_value and auth_type == "Cookie":
                headers.append("Cookie: %s" % auth_value)
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


# -- Pending endpoint runner (for confirmed mutating methods) ---------------

# -- Resend endpoint runner -------------------------------------------------

# -- Fuzz scan runner -------------------------------------------------------

class _FuzzScanRunner(Runnable):
    """For each endpoint x each wordlist value x each identity, send a request."""

    def __init__(self, extender, base, endpoints, auth_entries, wordlist, fuzz_type,
                 user_agent, batch_size, per_request_refresh, login_url):
        self._ext = extender
        self._base = base
        self._endpoints = endpoints
        self._auth_entries = auth_entries
        self._wordlist = wordlist
        self._fuzz_type = fuzz_type
        self._user_agent = user_agent
        self._batch_size = batch_size
        self._per_request_refresh = per_request_refresh
        self._login_url = login_url

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[FuzzScan] %s" % msg)
        except Exception:
            pass

    def run(self):
        import time
        helpers = self._ext._helpers
        total_ep = len(self._endpoints)
        total_words = len(self._wordlist)
        global_params = self._ext._globalParams

        self._log("Fuzz scan: %d endpoints, %d words, type=%s" % (
            total_ep, total_words, self._fuzz_type))

        for ep_idx, (label, method, path_template, param_defs) in enumerate(self._endpoints):
            if self._ext._autoScanStopped:
                break

            # Wait if paused
            while self._ext._autoScanPaused and not self._ext._autoScanStopped:
                time.sleep(0.3)
            if self._ext._autoScanStopped:
                break

            tab_data = self._ext._autoScanTabs[ep_idx]
            ep_num = ep_idx + 1

            class _Status(Runnable):
                def __init__(s):
                    s.msg = "Fuzz [%d/%d] %s -- %d words" % (ep_num, total_ep, label, total_words)
                def run(s):
                    self._ext._statusLabel.setText(s.msg)
                    tab_idx = ep_idx + 1
                    if tab_idx < self._ext._resultsTabbedPane.getTabCount():
                        self._ext._resultsTabbedPane.setSelectedIndex(tab_idx)
            SwingUtilities.invokeLater(_Status())

            # Build base params (from global params + swagger defaults)
            base_params = []
            for p in param_defs:
                value = global_params.get(p["name"], "")
                if not value and p.get("default"):
                    value = str(p["default"])
                if not value and p.get("required"):
                    value = p["name"]
                base_params.append({
                    "name": p["name"],
                    "in": p["in"],
                    "type": p.get("type", "string"),
                    "value": value,
                })

            # Populate the per-endpoint params table with base values
            class _FillTable(Runnable):
                def __init__(s):
                    s.td = tab_data; s.bp = base_params
                def run(s):
                    m = s.td.get("epParamModel")
                    if m:
                        m.setRowCount(0)
                        for pp in s.bp:
                            m.addRow([pp["name"], pp["in"], pp["value"]])
            SwingUtilities.invokeLater(_FillTable())

            # Find which params match the fuzz type
            fuzz_indices = []
            for pi, p in enumerate(base_params):
                if self._fuzz_type in p.get("type", "").lower():
                    fuzz_indices.append(pi)

            if not fuzz_indices:
                self._log("  [%s] No params of type '%s' -- skipping" % (label, self._fuzz_type))
                continue

            self._log("  [%s] Fuzzing %d params: %s" % (
                label, len(fuzz_indices),
                ", ".join(base_params[i]["name"] for i in fuzz_indices)))

            row_num = 0

            for word_idx, word in enumerate(self._wordlist):
                if self._ext._autoScanStopped:
                    break
                while self._ext._autoScanPaused and not self._ext._autoScanStopped:
                    time.sleep(0.3)
                if self._ext._autoScanStopped:
                    break

                # Build params with this word substituted for all matching type params
                fuzzed_params = []
                for pi, p in enumerate(base_params):
                    if pi in fuzz_indices:
                        fuzzed_params.append({
                            "name": p["name"], "in": p["in"], "value": word})
                    else:
                        fuzzed_params.append({
                            "name": p["name"], "in": p["in"], "value": p["value"]})

                # No-auth request
                row_num += 1
                self._sendOne(helpers, tab_data, row_num,
                    "[%s] <No Auth>" % word, None, None, "",
                    method, path_template, fuzzed_params)

                # Each identity
                for auth_name, auth_type, auth_value, auth_login_body in self._auth_entries:
                    if self._ext._autoScanStopped:
                        break
                    row_num += 1

                    # Per-request refresh
                    if self._per_request_refresh and auth_login_body and self._login_url:
                        refreshed = self._ext._doRefreshSession(
                            self._login_url, auth_login_body, auth_type)
                        if refreshed:
                            auth_value = refreshed

                    self._sendOne(helpers, tab_data, row_num,
                        "[%s] %s" % (word, auth_name),
                        auth_type, auth_value, auth_login_body,
                        method, path_template, fuzzed_params)

                    # Batch pause check
                    if self._batch_size > 0:
                        self._ext._requestCounter += 1
                        if self._ext._requestCounter % self._batch_size == 0:
                            class _Pause(Runnable):
                                def run(s):
                                    self._ext._resumeBtn.setEnabled(True)
                                    self._ext._statusLabel.setText(
                                        "Fuzz paused after %d requests. Click Resume." %
                                        self._ext._requestCounter)
                            SwingUtilities.invokeLater(_Pause())
                            self._ext._pauseSemaphore.acquire()

        # Done
        class _Done(Runnable):
            def run(s):
                self._ext._autoScanBtn.setEnabled(True)
                self._ext._fuzzScanBtn.setEnabled(True)
                self._ext._sendBtn.setEnabled(True)
                self._ext._pauseScanBtn.setEnabled(False)
                self._ext._stopScanBtn.setEnabled(False)
                self._ext._resumeBtn.setEnabled(False)
                if self._ext._autoScanStopped:
                    self._ext._statusLabel.setText("Fuzz scan stopped.")
                else:
                    self._ext._statusLabel.setText(
                        "Fuzz scan complete -- %d endpoints x %d words." % (
                            total_ep, total_words))
        SwingUtilities.invokeLater(_Done())

    def _sendOne(self, helpers, tab_data, row_num, identity,
                 auth_type, auth_value, login_body,
                 method, path_template, params):
        if self._ext._autoScanStopped:
            return
        import time
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
            if auth_value and auth_type == "Bearer":
                headers.append("Authorization: Bearer %s" % auth_value)
            elif auth_value and auth_type == "Cookie":
                headers.append("Cookie: %s" % auth_value)
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
            cur_row = row_num; err_msg = str(e)
            class _Err(Runnable):
                def __init__(s):
                    s.r = cur_row; s.id = identity; s.err = err_msg
                def run(s):
                    tab_data["model"].addRow([str(s.r), s.id, "ERR", "0", "0"])
                    tab_data["raw_requests"].append(None)
                    tab_data["raw_responses"].append(None)
                    tab_data["http_services"].append(None)
            SwingUtilities.invokeLater(_Err())


# -- Resend endpoint runner -------------------------------------------------

class _ResendEndpointRunner(Runnable):
    """Resends requests for a single endpoint with updated params."""

    def __init__(self, extender, tab_data, base, auth_entries, user_agent,
                 method, path_template, params, per_request_refresh=False, login_url=""):
        self._ext = extender
        self._tab = tab_data
        self._base = base
        self._auth_entries = auth_entries
        self._user_agent = user_agent
        self._method = method
        self._path_template = path_template
        self._params = params
        self._per_request_refresh = per_request_refresh
        self._login_url = login_url

    def run(self):
        import time
        helpers = self._ext._helpers
        tab_data = self._tab
        row_num = 0

        # Unauthenticated
        row_num += 1
        self._fire(helpers, tab_data, row_num, "<No Auth>", None, None, "")

        # Each auth identity
        for auth_name, auth_type, auth_value, auth_login_body in self._auth_entries:
            row_num += 1
            self._fire(helpers, tab_data, row_num, auth_name, auth_type, auth_value, auth_login_body)

        class _Done(Runnable):
            def run(s):
                self._ext._statusLabel.setText(
                    "Resend complete -- %s %s -- %d requests." % (
                        self._method, self._path_template, row_num))
        SwingUtilities.invokeLater(_Done())

    def _fire(self, helpers, tab_data, row_num, identity, auth_type, auth_value, login_body=""):
        import time
        # Per-request refresh if enabled
        if self._per_request_refresh and login_body and self._login_url:
            refreshed = self._ext._doRefreshSession(self._login_url, login_body, auth_type)
            if refreshed:
                auth_value = refreshed
                self._ext._callbacks.printOutput(
                    "[PendingRefresh] Refreshed '%s' before request" % identity)
        try:
            path = self._path_template
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
                "%s %s HTTP/1.1" % (self._method, path_for_request),
                "Host: %s" % host,
            ]
            if auth_value and auth_type == "Bearer":
                headers.append("Authorization: Bearer %s" % auth_value)
            elif auth_value and auth_type == "Cookie":
                headers.append("Cookie: %s" % auth_value)
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


# -- Pending endpoint runner (for confirmed mutating methods) ---------------

class _PendingEndpointRunner(Runnable):
    """Sends requests for a single endpoint after user confirmation."""

    def __init__(self, extender, tab_data, base, auth_entries, banner_panel, user_agent="Swagger_Tester/1.0", per_request_refresh=False, login_url=""):
        self._ext = extender
        self._tab = tab_data
        self._base = base
        self._auth_entries = auth_entries  # list of (name, type, value)
        self._banner = banner_panel
        self._user_agent = user_agent
        self._per_request_refresh = per_request_refresh
        self._login_url = login_url

    def run(self):
        import time
        helpers = self._ext._helpers
        method = self._tab["method"]
        path_template = self._tab["path_template"]
        params = self._tab["params"]

        row_num = 0

        # Unauthenticated
        row_num += 1
        self._fire(helpers, row_num, "<No Auth>", None, None,
                   method, path_template, params)

        # Each auth identity
        for auth_name, auth_type, auth_value, auth_login_body in self._auth_entries:
            row_num += 1
            self._fire(helpers, row_num, auth_name, auth_type, auth_value, auth_login_body)

        # Update banner to done
        class _Done(Runnable):
            def run(s):
                for comp in self._banner.getComponents():
                    if isinstance(comp, JLabel):
                        comp.setText("  Done -- %d requests sent  " % row_num)
                self._ext._statusLabel.setText(
                    "Confirmed %s %s -- %d request(s) sent." % (
                        method, path_template, row_num))
        SwingUtilities.invokeLater(_Done())

    def _fire(self, helpers, row_num, identity, auth_type, auth_value,
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
            if auth_value and auth_type == "Bearer":
                headers.append("Authorization: Bearer %s" % auth_value)
            elif auth_value and auth_type == "Cookie":
                headers.append("Cookie: %s" % auth_value)
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


# -- Background request runner ----------------------------------------------

class _RequestRunner(Runnable):
    def __init__(self, extender, base, method, path_template, params, auth_entries, user_agent="Swagger_Tester/1.0", batch_size=0, per_request_refresh=False, login_url=""):
        self._ext = extender
        self._base = base
        self._method = method
        self._path = path_template
        self._params = params
        self._auth_entries = auth_entries  # list of (name, type, value, login_body)
        self._user_agent = user_agent
        self._batch_size = batch_size
        self._per_request_refresh = per_request_refresh
        self._login_url = login_url

    def _log(self, msg):
        try:
            self._ext._callbacks.printOutput("[Swagger_Tester] %s" % msg)
        except Exception:
            pass

    def run(self):
        import time

        total = len(self._auth_entries) + 1  # +1 for unauthenticated

        try:
            self._log("Starting %d request(s)..." % total)
            row_num = 0

            # -- First: unauthenticated request (no JWT) -----------------
            row_num += 1
            try:
                self._checkPause(row_num, total)
                result = self._doRequest(None, None)
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

            # -- Then: one request per auth identity ----------------------
            for i, (auth_name, auth_type, auth_value, auth_login_body) in enumerate(self._auth_entries):
                row_num += 1
                cur_row = row_num
                display_name = auth_name
                try:
                    self._checkPause(cur_row, total)
                    # Per-request refresh if enabled
                    if self._per_request_refresh and auth_login_body and self._login_url:
                        refreshed = self._ext._doRefreshSession(self._login_url, auth_login_body, auth_type)
                        if refreshed:
                            auth_value = refreshed
                            self._log("[%s] refreshed auth before request" % auth_name)
                    result = self._doRequest(auth_type, auth_value)
                    status, size, elapsed, body, req_text, raw_req, raw_resp, svc = result
                    self._log("[%s] done: status=%s" % (auth_name, str(status)))

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
                    self._log("[%s] error: %s" % (auth_name, str(e)))
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
                    "Done -- %d request(s) sent (1 unauthenticated + %d with auth)." % (total, len(self._auth_entries)))
        SwingUtilities.invokeLater(_Done())

    def _checkPause(self, current_row, total):
        """Check if we should pause for batch limit."""
        if self._batch_size > 0:
            self._ext._requestCounter += 1
            if self._ext._requestCounter % self._batch_size == 0:
                class _Pause(Runnable):
                    def run(s):
                        self._ext._resumeBtn.setEnabled(True)
                        self._ext._statusLabel.setText(
                            "Paused after %d requests (batch size %d). Click Resume to continue. [%d/%d]" % (
                                self._ext._requestCounter, self._batch_size, current_row, total))
                SwingUtilities.invokeLater(_Pause())
                self._ext._pauseSemaphore.acquire()

    def _doRequest(self, auth_type, auth_value):
        import time
        helpers = self._ext._helpers

        # -- Build URL path (substitute path params) ----------------------
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

        # -- Build raw HTTP request ---------------------------------------
        path_for_request = url_obj.getPath()
        if url_obj.getQuery():
            path_for_request += "?" + url_obj.getQuery()
        if not path_for_request:
            path_for_request = "/"

        headers = [
            "%s %s HTTP/1.1" % (self._method, path_for_request),
            "Host: %s" % host,
        ]
        if auth_value and auth_type == "Bearer":
            headers.append("Authorization: Bearer %s" % auth_value)
        elif auth_value and auth_type == "Cookie":
            headers.append("Cookie: %s" % auth_value)
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

        # -- Send via Burp ------------------------------------------------
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

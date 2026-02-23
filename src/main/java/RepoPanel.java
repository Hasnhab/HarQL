package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Main panel for managing harvested GraphQL variables and injection rules.
 */

public class RepoPanel extends JPanel {
    private final InMemoryEngine engine;
    private final MontoyaApi api;
    private JTable table;
    private DefaultTableModel model;
    private JComboBox<String> typeCombo;
    private JTextField searchField;
    private TableRowSorter<DefaultTableModel> sorter;
    private JScrollPane scrollPane;
    private int lastScrollPosition = 0;

    private JCheckBox useInjectionCheck;
    private JTextArea rulesBulkArea;
    private JButton applyRulesButton;
    private JButton resetAllButton;
    private JButton exportRulesBtn;
    private JButton importRulesBtn;

    private boolean previewMode = false;
	
	/**
     * Creates the Repo/Command Center panel with table, rules editor, and export features.
     *
     * @param engine InMemoryEngine instance
     * @param api Montoya API instance
     */

    public RepoPanel(InMemoryEngine engine, MontoyaApi api) {
        this.engine = engine;
        this.api = api;
        setLayout(new BorderLayout());
         // Top controls
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel leftTop = new JPanel(new FlowLayout(FlowLayout.LEFT));
        typeCombo = new JComboBox<>(new String[]{"Repo", "Session"});
        typeCombo.addActionListener(e -> refresh());
        leftTop.add(new JLabel("View:"));
        leftTop.add(typeCombo);

        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchPanel.add(new JLabel("Search:"));
        searchField = new JTextField(22);
        searchPanel.add(searchField);

        JButton exportButton = new JButton("Export");
        exportButton.addActionListener(e -> showExportOptions());
        searchPanel.add(exportButton);

        topPanel.add(leftTop, BorderLayout.WEST);
        topPanel.add(searchPanel, BorderLayout.EAST);
        // Rules & presets panel
        JPanel rulesPanel = new JPanel(new BorderLayout(5, 5));
        rulesPanel.setBorder(BorderFactory.createTitledBorder("Injection Rules"));

        rulesBulkArea = new JTextArea(5, 70);
        rulesBulkArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        rulesBulkArea.setLineWrap(true);
        rulesBulkArea.setWrapStyleWord(true);
        JScrollPane rulesScroll = new JScrollPane(rulesBulkArea);

        JPanel rulesControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        useInjectionCheck = new JCheckBox("Apply injections on export", true);
        applyRulesButton = new JButton("Apply Rules");
        resetAllButton = new JButton("Reset All to Raw");
        exportRulesBtn = new JButton("Export Rules JSON");
        importRulesBtn = new JButton("Import Rules JSON");

        applyRulesButton.addActionListener(e -> applyBulkRules());
        resetAllButton.addActionListener(e -> resetAllToRaw());
        exportRulesBtn.addActionListener(e -> exportRulesJson());
        importRulesBtn.addActionListener(e -> importRulesJson());

        rulesControls.add(new JLabel("Bulk Rules (key=value)"));
        rulesControls.add(useInjectionCheck);
        rulesControls.add(applyRulesButton);
        rulesControls.add(resetAllButton);
        rulesControls.add(exportRulesBtn);
        rulesControls.add(importRulesBtn);

        rulesPanel.add(rulesScroll, BorderLayout.CENTER);
        rulesPanel.add(rulesControls, BorderLayout.SOUTH);
		JButton clearRulesBtn = new JButton("Clear All Rules");
        clearRulesBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this,
    "Clear all injection rules?\n\nThis action cannot be undone.",
    "Clear Rules",
    JOptionPane.OK_CANCEL_OPTION,
    JOptionPane.WARNING_MESSAGE);

if (confirm == JOptionPane.OK_OPTION) {
    engine.clearAllRules();
    rulesBulkArea.setText("");
}
        });
        rulesControls.add(clearRulesBtn);

        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(topPanel, BorderLayout.NORTH);
        northPanel.add(rulesPanel, BorderLayout.CENTER);
        add(northPanel, BorderLayout.NORTH);

        model = new DefaultTableModel(new Object[]{"#", "Doc ID", "Variables", "Module", "Host", "Src"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(200);
        table.getColumnModel().getColumn(2).setPreferredWidth(520);
        table.getColumnModel().getColumn(3).setPreferredWidth(280);
        table.getColumnModel().getColumn(4).setPreferredWidth(160);
        table.getColumnModel().getColumn(5).setPreferredWidth(380);

        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
		sorter.setComparator(0, (o1, o2) -> {
    if (o1 == null && o2 == null) return 0;
    if (o1 == null) return -1;
    if (o2 == null) return 1;

    if (o1 instanceof Number && o2 instanceof Number) {
        return Integer.compare(((Number) o1).intValue(), ((Number) o2).intValue());
    }

    try {
        int i1 = Integer.parseInt(o1.toString());
        int i2 = Integer.parseInt(o2.toString());
        return Integer.compare(i1, i2);
    } catch (Exception e) {
        return o1.toString().compareTo(o2.toString());
    }
 });

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
            private void applyFilter() {
                String text = searchField.getText().trim();
                sorter.setRowFilter(text.isEmpty() ? null : RowFilter.regexFilter("(?i)" + text));
            }
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = table.getSelectedRow();
                    if (viewRow != -1) {
                        int modelRow = table.convertRowIndexToModel(viewRow);
                        showDetailDialog(modelRow);
                    }
                }
            }
        });

        scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        refresh();
    }

    private void exportRulesJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Injection Rules");
        chooser.setSelectedFile(new File("injection_rules.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().endsWith(".json")) file = new File(file.getAbsolutePath() + ".json");

            try (FileWriter writer = new FileWriter(file)) {
                writer.write(engine.exportRulesAsJson());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importRulesJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Injection Rules");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                String content = new String(Files.readAllBytes(file.toPath()));
                engine.importRulesFromJson(content);
				rulesBulkArea.setText(engine.getRulesAsBulkText());
                
               
                rulesBulkArea.repaint();
                
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
 

    private void applyBulkRules() {

    String bulk = rulesBulkArea.getText().trim();
    if (bulk.isEmpty()) {
        JOptionPane.showMessageDialog(this,
    "Please enter at least one rule (format: key=value)",
    "No Rules Entered",
    JOptionPane.WARNING_MESSAGE);
        return;
    }

    engine.loadRules(bulk);

    engine.applyInjectionToDataset("Repo".equals(typeCombo.getSelectedItem()));

    refresh();

 }

    private void resetAllToRaw() {
    boolean isRepo = "Repo".equals(typeCombo.getSelectedItem());
    engine.resetAllToRaw(isRepo);
    refresh();
}

    

    private void refreshWithPreview() {
        lastScrollPosition = scrollPane.getVerticalScrollBar().getValue();

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                String view = (String) typeCombo.getSelectedItem();
                List<Map<String, Object>> itemsList = view.equals("Repo") ? engine.getRepo() : engine.getSession();

                model.setRowCount(0);

                for (int i = 0; i < itemsList.size(); i++) {
                    Map<String, Object> it = itemsList.get(i);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> varsMap = (Map<String, Object>) it.getOrDefault("variables", new java.util.HashMap<>());

                    Map<String, Object> displayVars = previewMode ? engine.applyInjection(varsMap) : varsMap;

                    String vars = "{}";
                    try {
                        vars = mapToJsonRecursive(displayVars).toString(2);
                    } catch (Exception e) {
                        vars = displayVars.toString();
                    }

                           model.addRow(new Object[]{
                           Integer.valueOf(i + 1),
                            it.getOrDefault("doc_id", "N/A").toString(),
                            vars,
                            it.getOrDefault("module", "").toString(),
                            it.getOrDefault("host", "").toString(),
                            it.getOrDefault("src", "").toString()
                    });
                }
                return null;
            }

            @Override
            protected void done() {
                SwingUtilities.invokeLater(() -> {
                    scrollPane.getVerticalScrollBar().setValue(lastScrollPosition);
                    table.repaint();
                });
            }
        }.execute();
    }
/**
     * Refreshes the table with current repo or session data.
     */
    public void refresh() {

    lastScrollPosition = scrollPane.getVerticalScrollBar().getValue();

    List<? extends RowSorter.SortKey> sortKeys = sorter.getSortKeys();

    new SwingWorker<Void, Void>() {
        @Override
        protected Void doInBackground() {

            String view = (String) typeCombo.getSelectedItem();
            List<Map<String, Object>> itemsList =
                    view.equals("Repo") ? engine.getRepo() : engine.getSession();

            model.setRowCount(0);

            for (int i = 0; i < itemsList.size(); i++) {

                Map<String, Object> it = itemsList.get(i);

                @SuppressWarnings("unchecked")
                Map<String, Object> varsMap =
                        (Map<String, Object>) it.getOrDefault("variables",
                                new java.util.HashMap<>());

                Map<String, Object> displayVars = varsMap;

                String vars;
                try {
                    vars = mapToJsonRecursive(displayVars).toString(2);
                } catch (Exception e) {
                    vars = displayVars.toString();
                }

                model.addRow(new Object[]{
                        Integer.valueOf(i + 1),
                        it.getOrDefault("doc_id", "N/A").toString(),
                        vars,
                        it.getOrDefault("module", "").toString(),
                        it.getOrDefault("host", "").toString(),
                        it.getOrDefault("src", "").toString()
                });
            }

            return null;
        }

        @Override
        protected void done() {
            SwingUtilities.invokeLater(() -> {

                sorter.setSortKeys(sortKeys);
                sorter.sort();

                scrollPane.getVerticalScrollBar()
                          .setValue(lastScrollPosition);

                table.repaint();
            });
        }
    }.execute();
 }

/**
     * Updates the bulk rules text area from the engine's current rules.
     */
    public void updateRulesTextAreaFromEngine() {
      rulesBulkArea.setText(engine.getRulesAsBulkText());
    }

    private void showExportOptions() {
        String view = (String) typeCombo.getSelectedItem();
        boolean useInjection = useInjectionCheck.isSelected();

        String[] options = {"JSON", "CSV", "Pitchfork Payloads", "Cancel"};
        int choice = JOptionPane.showOptionDialog(
                this,
               "Export " + view + (useInjection ? " – Injected" : " – Raw"),
                "Export",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == 0) exportAsJson(view, useInjection);
        else if (choice == 1) exportAsCsv(view, useInjection);
        else if (choice == 2) exportAsPitchfork(view, useInjection);
    }

    private void exportAsJson(String view, boolean useInjection) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export " + view + " as JSON");
        chooser.setSelectedFile(new File(view.toLowerCase() + ".json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        if (!file.getName().endsWith(".json")) file = new File(file.getAbsolutePath() + ".json");

        List<Map<String, Object>> data = view.equals("Repo") ? engine.getRepo() : engine.getSession();
        JSONArray jsonArray = new JSONArray();

        for (Map<String, Object> item : data) {
            JSONObject itemJson = new JSONObject();
            for (Map.Entry<String, Object> entry : item.entrySet()) {
                Object value = entry.getValue();
                if ("variables".equals(entry.getKey()) && value instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vars = (Map<String, Object>) value;
                    if (useInjection) vars = engine.applyInjection(vars);
                    value = mapToJsonRecursive(vars);
                }
                itemJson.put(entry.getKey(), value);
            }
            jsonArray.put(itemJson);
        }

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(jsonArray.toString(2));
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportAsCsv(String view, boolean useInjection) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export " + view + " as CSV");
        chooser.setSelectedFile(new File(view.toLowerCase() + ".csv"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        if (!file.getName().endsWith(".csv")) file = new File(file.getAbsolutePath() + ".csv");

        try (FileWriter writer = new FileWriter(file)) {
            writer.write("\"#\",\"Doc ID\",\"Variables\",\"Module\",\"Host\",\"Src\"\n");

            List<Map<String, Object>> data = view.equals("Repo") ? engine.getRepo() : engine.getSession();
            for (int i = 0; i < data.size(); i++) {
                Map<String, Object> it = data.get(i);
                @SuppressWarnings("unchecked")
                Map<String, Object> varsMap = (Map<String, Object>) it.getOrDefault("variables", new java.util.HashMap<>());

                if (useInjection) varsMap = engine.applyInjection(varsMap);

                String varsStr = "{}";
                try {
                    varsStr = mapToJsonRecursive(varsMap).toString(2).replace("\"", "\"\"");
                } catch (Exception ignored) {}

                writer.append(String.valueOf(i + 1)).append(',')
                      .append(escapeCsv((String) it.getOrDefault("doc_id", "N/A"))).append(',')
                      .append("\"").append(varsStr).append("\"").append(',')
                      .append(escapeCsv((String) it.getOrDefault("module", ""))).append(',')
                      .append(escapeCsv((String) it.getOrDefault("host", ""))).append(',')
                      .append(escapeCsv((String) it.getOrDefault("src", ""))).append('\n');
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportAsPitchfork(String view, boolean useInjection) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select folder to export Pitchfork payloads");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File folder = chooser.getSelectedFile();
        File docIdsFile = new File(folder, "doc_ids.txt");
        File variablesFile = new File(folder, "variables.txt");

        try (FileWriter docWriter = new FileWriter(docIdsFile);
             FileWriter varsWriter = new FileWriter(variablesFile)) {

            List<Map<String, Object>> data = view.equals("Repo") ? engine.getRepo() : engine.getSession();
            for (Map<String, Object> it : data) {
                String docId = (String) it.getOrDefault("doc_id", "");
                if (docId.isEmpty() || "N/A".equals(docId)) continue;

                @SuppressWarnings("unchecked")
                Map<String, Object> varsMap = (Map<String, Object>) it.getOrDefault("variables", new java.util.HashMap<>());
                if (useInjection) varsMap = engine.applyInjection(varsMap);

                docWriter.write(docId + "\n");

                try {
                    JSONObject varsJson = mapToJsonRecursive(varsMap);
                    String encoded = URLEncoder.encode(varsJson.toString(), StandardCharsets.UTF_8);
                    varsWriter.write(encoded + "\n");
                } catch (Exception e) {
                    varsWriter.write("\n");
                }
            }

            JOptionPane.showMessageDialog(this,
    "Pitchfork payloads exported.\n\n" +
    "doc_ids.txt     → §PAYLOAD1§\n" +
    "variables.txt   → §PAYLOAD2§ (URL-encoded)",
    "Export Complete",
    JOptionPane.INFORMATION_MESSAGE);

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JSONObject mapToJsonRecursive(Map<String, Object> map) {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object v = entry.getValue();
            if (v instanceof Map) v = mapToJsonRecursive((Map<String, Object>) v);
            else if (v instanceof List) v = listToJsonRecursive((List<Object>) v);
            else if (v == null) v = JSONObject.NULL;
            json.put(entry.getKey(), v);
        }
        return json;
    }

    private JSONArray listToJsonRecursive(List<Object> list) {
        JSONArray array = new JSONArray();
        for (Object o : list) {
            if (o instanceof Map) o = mapToJsonRecursive((Map<String, Object>) o);
            else if (o instanceof List) o = listToJsonRecursive((List<Object>) o);
            else if (o == null) o = JSONObject.NULL;
            array.put(o);
        }
        return array;
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private void showDetailDialog(int modelRow) {
        String docId = (String) model.getValueAt(modelRow, 1);
        String originalVars = (String) model.getValueAt(modelRow, 2);
        String module = (String) model.getValueAt(modelRow, 3);
        String host = (String) model.getValueAt(modelRow, 4);
        String src = (String) model.getValueAt(modelRow, 5);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Operation Details", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(1000, 750);
        dialog.setLocationRelativeTo(this);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel infoPanel = new JPanel(new GridLayout(4, 2, 10, 10));
        infoPanel.setBorder(BorderFactory.createTitledBorder("Query Information"));
        infoPanel.add(new JLabel("Doc ID:")); JTextField docField = new JTextField(docId); docField.setEditable(false); infoPanel.add(docField);
        infoPanel.add(new JLabel("Module:")); JTextField modField = new JTextField(module); modField.setEditable(false); infoPanel.add(modField);
        infoPanel.add(new JLabel("Host:"));   JTextField hostField = new JTextField(host); hostField.setEditable(false); infoPanel.add(hostField);
        infoPanel.add(new JLabel("Source:")); JTextField srcField = new JTextField(src); srcField.setEditable(false); infoPanel.add(srcField);

        mainPanel.add(infoPanel, BorderLayout.NORTH);

        JPanel varsPanel = new JPanel(new BorderLayout());
        varsPanel.setBorder(BorderFactory.createTitledBorder("Variables (Editable)"));
        JTextArea varsArea = new JTextArea(originalVars, 22, 80);
        varsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
        varsArea.setLineWrap(false);
        varsArea.setEditable(true);
        JScrollPane varsScroll = new JScrollPane(varsArea);
        varsPanel.add(varsScroll, BorderLayout.CENTER);
        mainPanel.add(varsPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton resetButton = new JButton("Reset to Original");
        resetButton.addActionListener(e -> varsArea.setText(originalVars));
        buttonPanel.add(resetButton);

        JButton saveButton = new JButton("Save Injection to Table");
        saveButton.addActionListener(e -> {
            try {
                new JSONObject(varsArea.getText());

                // Support both Repo and Session views correctly
                String currentView = (String) typeCombo.getSelectedItem();
                List<Map<String, Object>> sourceList = "Repo".equals(currentView) 
                        ? engine.getRepo() 
                        : engine.getSession();

                @SuppressWarnings("unchecked")
                Map<String, Object> vars = (Map<String, Object>) sourceList.get(modelRow).get("variables");

                String bulk = engine.exportVariablesAsBulkRules(vars);

                rulesBulkArea.setText(
                    rulesBulkArea.getText().isEmpty()
                        ? bulk
                        : rulesBulkArea.getText() + "\n" + bulk
                );

                JOptionPane.showMessageDialog(dialog, "Injection saved.", "Done", JOptionPane.INFORMATION_MESSAGE);

            } catch (JSONException ex) {
                JOptionPane.showMessageDialog(dialog, "Invalid JSON: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        buttonPanel.add(saveButton);

        JButton sendButton = new JButton("Send to Repeater");
        sendButton.addActionListener(e -> sendToRepeater(docId, varsArea.getText(), module, dialog));
        buttonPanel.add(sendButton);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        dialog.add(mainPanel);
        dialog.setVisible(true);
    }

    private void sendToRepeater(String docId, String varsStr, String module, JDialog parentDialog) {
        if (docId.equals("N/A") || docId.isEmpty()) {
            JOptionPane.showMessageDialog(parentDialog, "Cannot send: Invalid or missing Doc ID.", "Invalid Input", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        HttpRequest baseRequest = null;
        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse entry = history.get(i);
            HttpRequest req = entry.request();
            if ("POST".equals(req.method()) && req.path().contains("/api/graphql")) {
                baseRequest = req;
                break;
            }
        }

        if (baseRequest == null) {
            JOptionPane.showMessageDialog(parentDialog, "No recent GraphQL POST request found in proxy history.", "Cannot Send", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            JSONObject variablesJson = varsStr.trim().equals("{}") || varsStr.trim().isEmpty()
                    ? new JSONObject() : new JSONObject(varsStr);
            String encodedVariables = URLEncoder.encode(variablesJson.toString(), StandardCharsets.UTF_8);

            HttpRequest newRequest = baseRequest
                    .withParameter(HttpParameter.bodyParameter("doc_id", docId))
                    .withParameter(HttpParameter.bodyParameter("variables", encodedVariables));

            if (!module.isEmpty()) {
                newRequest = newRequest.withParameter(HttpParameter.bodyParameter("fb_api_req_friendly_name", module));
                newRequest = newRequest.withHeader("X-Fb-Friendly-Name", module);
            }

            String tabName = "GraphQL – " + docId.substring(0, Math.min(8, docId.length()));
            api.repeater().sendToRepeater(newRequest, tabName);
            JOptionPane.showMessageDialog(parentDialog, "Sent to Repeater.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parentDialog, "Failed to send to Repeater: " + ex.getMessage(), "Send Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
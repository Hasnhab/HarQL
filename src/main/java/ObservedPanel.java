package burp;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * Panel displaying repeated variables insight from GraphQL traffic.
 */

public class ObservedPanel extends JPanel {
    private final InMemoryEngine engine;
    private JTable repeatedTable;
    private DefaultTableModel repeatedModel;
    private JScrollPane scrollPane;

/**
     * Creates the Observed panel with repeated variables table.
     *
     * @param engine InMemoryEngine instance
     */
    public ObservedPanel(InMemoryEngine engine) {
        this.engine = engine;
        setLayout(new BorderLayout());

        JLabel title = new JLabel("Variable Insights - Repeated Variables from GraphQL Traffic");
        title.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(title, BorderLayout.NORTH);

        repeatedModel = new DefaultTableModel(
        new Object[]{"Parameter", "Count", "Most Frequent Value", "Action"}, 0) {
    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 3;
    }
 };

        repeatedTable = new JTable(repeatedModel);
        repeatedTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        repeatedTable.getColumnModel().getColumn(0).setPreferredWidth(280);
        repeatedTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        repeatedTable.getColumnModel().getColumn(2).setPreferredWidth(350);
        repeatedTable.getColumnModel().getColumn(3).setPreferredWidth(160);
        repeatedTable.getColumn("Action").setCellRenderer(new ButtonRenderer());
        repeatedTable.getColumn("Action")
             .setCellEditor(new ButtonEditor());

        scrollPane = new JScrollPane(repeatedTable);
        add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton sendAllButton = new JButton("Send All to Rules");
        sendAllButton.addActionListener(e -> sendAllToRules());
        bottomPanel.add(sendAllButton);
        add(bottomPanel, BorderLayout.SOUTH);

        refresh();
    }
	private void syncRulesTextArea() {

    Container parent = getParent();
    while (parent != null && !(parent instanceof MainTab)) {
        parent = parent.getParent();
    }

    if (parent instanceof MainTab) {
        RepoPanel repoPanel = ((MainTab) parent).getRepoPanel();
        if (repoPanel != null) {
            repoPanel.updateRulesTextAreaFromEngine();
        }
    }
 }

    private void sendAllToRules() {
        int count = repeatedModel.getRowCount();
        int added = 0;
        for (int row = 0; row < count; row++) {
            String param = (String) repeatedModel.getValueAt(row, 0);
            Object value = repeatedModel.getValueAt(row, 2);
            if (value != null) {
                engine.addRule(param, value);
                added++;
            }
			
        }
		syncRulesTextArea();
        JOptionPane.showMessageDialog(this,
    added + " rule" + (added == 1 ? "" : "s") + " added to injection rules.",
    "Rules Added",
    JOptionPane.INFORMATION_MESSAGE);

       
    }
/**
     * Refreshes the table with latest repeated variables insight.
     */
    public void refresh() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                List<Map<String, Object>> insight = engine.getRepeatedVariablesInsight();
                repeatedModel.setRowCount(0);
                for (Map<String, Object> rowData : insight) {
                    repeatedModel.addRow(new Object[]{
                            rowData.get("parameter"),
                            rowData.get("count"),
                            rowData.get("most_frequent_value"),
                            "Send to Rules"
                    });
                }
                return null;
            }
            @Override
            protected void done() {
                repeatedTable.repaint();
            }
        }.execute();
    }

    class ButtonRenderer extends JButton implements TableCellRenderer {

    public ButtonRenderer() {
        setOpaque(true);
        setFocusPainted(false);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {

        setText("Send to Rules");
        setBackground(UIManager.getColor("Button.background"));
        return this;
    }
 }

    class ButtonEditor extends AbstractCellEditor implements TableCellEditor {

    private final JButton button = new JButton("Send to Rules");
    private int currentRow;

    public ButtonEditor() {

        button.setFocusPainted(false);

        button.addActionListener(e -> {
            sendSingleRule(currentRow);
            fireEditingStopped();
        });
    }

    @Override
    public Object getCellEditorValue() {
        return "Send to Rules";
    }

    @Override
    public Component getTableCellEditorComponent(JTable table,
                                                 Object value,
                                                 boolean isSelected,
                                                 int row,
                                                 int column) {

        currentRow = table.convertRowIndexToModel(row);
        return button;
    }
 }

    private void sendSingleRule(int modelRow) {

    String param = (String) repeatedModel.getValueAt(modelRow, 0);
    Object value = repeatedModel.getValueAt(modelRow, 2);

    if (value != null) {
        engine.addRule(param, value);
        syncRulesTextArea();

        JOptionPane.showMessageDialog(this,
    "Rule added: " + param,
    "Rule Added",
    JOptionPane.INFORMATION_MESSAGE);

       
    }
 }

    private void refreshMainTab() {
        Container parent = getParent();
        while (parent != null && !(parent instanceof MainTab)) {
            parent = parent.getParent();
        }
        if (parent instanceof MainTab) {
            ((MainTab) parent).refreshAllTabs();
        }
    }
}
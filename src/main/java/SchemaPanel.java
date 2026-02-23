package burp;

import burp.api.montoya.MontoyaApi;
import com.mxgraph.layout.mxCompactTreeLayout;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;
import org.json.JSONArray;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Panel for viewing and exporting the inferred GraphQL schema.
 */

public class SchemaPanel extends JPanel {
    private final InMemoryEngine engine;
    private final MontoyaApi api;
    private JTextArea sdlArea;
    private mxGraphComponent graphComponent;
    private mxGraph graph;
    private Map<String, Map<String, String>> operationsData;
    private final Map<Object, Boolean> expandedState = new HashMap<>();

/**
     * Creates the Schema panel with SDL text view and interactive graph.
     *
     * @param engine InMemoryEngine instance
     * @param api Montoya API instance
     */
    public SchemaPanel(InMemoryEngine engine, MontoyaApi api) {
        this.engine = engine;
        this.api = api;
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshButton = new JButton("Refresh Schema");
        refreshButton.addActionListener(e -> refreshSchema());
        topPanel.add(refreshButton);

        JButton copySdlButton = new JButton("Copy SDL");
        copySdlButton.addActionListener(e -> {
            sdlArea.selectAll();
            sdlArea.copy();
            JOptionPane.showMessageDialog(this, "SDL copied to clipboard!");
        });
        topPanel.add(copySdlButton);

        JButton exportSdlButton = new JButton("Export SDL File");
        exportSdlButton.addActionListener(e -> exportSDL());
        topPanel.add(exportSdlButton);

        add(topPanel, BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.4);

        JPanel sdlPanel = new JPanel(new BorderLayout());
        sdlPanel.setBorder(BorderFactory.createTitledBorder("GraphQL SDL"));
        sdlArea = new JTextArea();
        sdlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        sdlArea.setEditable(false);
        sdlArea.setLineWrap(false);
        sdlPanel.add(new JScrollPane(sdlArea), BorderLayout.CENTER);
        splitPane.setLeftComponent(sdlPanel);

        JPanel graphPanel = new JPanel(new BorderLayout());
        graphPanel.setBorder(BorderFactory.createTitledBorder("Interactive Schema Graph (Double-click to expand)"));
        graph = new mxGraph();
        graph.setAllowDanglingEdges(false);
        graph.setCellsResizable(false);
        graph.setCellsEditable(false);
        graphComponent = new mxGraphComponent(graph);
        graphComponent.setConnectable(false);
        graphComponent.setPanning(true);
        graphComponent.setToolTips(true);

        graphComponent.getGraphControl().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    Object cell = graphComponent.getCellAt(e.getX(), e.getY());
                    if (cell != null && graph.getModel().isVertex(cell)) {
                        Boolean expanded = expandedState.get(cell);
                        if (expanded == null || !expanded) {
                            expandNode(cell);
                        } else {
                            collapseNode(cell);
                        }
                    }
                }
            }
        });

        graphPanel.add(graphComponent, BorderLayout.CENTER);
        splitPane.setRightComponent(graphPanel);

        add(splitPane, BorderLayout.CENTER);
        refreshSchema();
    }
	
	/**
     * Refreshes the SDL text and schema graph from current repo data.
     */

    public void refreshSchema() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                List<Map<String, Object>> repoList = engine.getRepo();
                GraphQLSchemaBuilder builder = new GraphQLSchemaBuilder();
                String sdl = builder.buildSDL(repoList);
                operationsData = builder.getOperationsData();

                SwingUtilities.invokeLater(() -> {
                    sdlArea.setText(sdl);
                    sdlArea.setCaretPosition(0);
                    buildHighLevelGraph();
                });
                return null;
            }
        }.execute();
    }

    private void buildHighLevelGraph() {
        graph.getModel().beginUpdate();
        try {
            graph.removeCells(graph.getChildCells(graph.getDefaultParent()));
            expandedState.clear();

            Object parent = graph.getDefaultParent();
            Object queryRoot = graph.insertVertex(parent, null, "Query (Root)", 100, 50, 140, 50,
                    "fillColor=#BBDEFB;strokeColor=#2196F3");

            int y = 150;
            for (String opName : operationsData.keySet()) {
                Object opVertex = graph.insertVertex(parent, null, opName, 300, y, 160, 40,
                        "fillColor=#C8E6C9;strokeColor=#4CAF50");
                graph.insertEdge(parent, null, "hasOperation", queryRoot, opVertex);
                expandedState.put(opVertex, false);
                y += 60;
            }

            mxCompactTreeLayout layout = new mxCompactTreeLayout(graph);
            layout.setHorizontal(false);
            layout.execute(parent);
        } finally {
            graph.getModel().endUpdate();
        }
        graphComponent.zoomTo(0.8, true);
    }

    private void expandNode(Object vertex) {
        String opName = (String) graph.getModel().getValue(vertex);
        Map<String, String> args = operationsData.get(opName);
        if (args == null || args.isEmpty()) return;

        graph.getModel().beginUpdate();
        try {
            int y = 200;
            for (Map.Entry<String, String> arg : args.entrySet()) {
                String label = arg.getKey() + ": " + arg.getValue();
                Object argVertex = graph.insertVertex(graph.getDefaultParent(), null, label, 500, y, 140, 30,
                        "fillColor=#FFCCBC;strokeColor=#FF5722");
                graph.insertEdge(graph.getDefaultParent(), null, "arg", vertex, argVertex);
                y += 40;
            }
            expandedState.put(vertex, true);

            mxCompactTreeLayout layout = new mxCompactTreeLayout(graph);
            layout.setHorizontal(false);
            layout.execute(graph.getDefaultParent());
        } finally {
            graph.getModel().endUpdate();
        }
    }

    private void collapseNode(Object vertex) {
        graph.getModel().beginUpdate();
        try {
            List<Object> toRemove = new ArrayList<>();
            Object[] edges = graph.getOutgoingEdges(vertex);
            for (Object edge : edges) {
                Object target = graph.getModel().getTerminal(edge, false);
                if (target != null) toRemove.add(target);
                toRemove.add(edge);
            }
            graph.removeCells(toRemove.toArray());
            expandedState.put(vertex, false);

            mxCompactTreeLayout layout = new mxCompactTreeLayout(graph);
            layout.setHorizontal(false);
            layout.execute(graph.getDefaultParent());
        } finally {
            graph.getModel().endUpdate();
        }
    }

    private void exportSDL() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Inferred Schema");
        chooser.setSelectedFile(new File("inferred_schema.graphql"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(sdlArea.getText());
                JOptionPane.showMessageDialog(this, "SDL exported successfully!");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
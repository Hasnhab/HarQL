package burp;

import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import javax.swing.event.ChangeListener;
import java.awt.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import java.awt.Desktop;

/**
 * Main tab container for the GraphQL Harvester extension.
 */

public class MainTab extends JPanel {
    private final ObservedPanel observedPanel;
    private final RepoPanel repoPanel;
    private final InMemoryEngine engine;
    private final JTabbedPane tabs;
	private final SchemaPanel schemaPanel;
	public RepoPanel getRepoPanel() {
    return repoPanel;
 }
	
	public void refreshAllTabs() {
        refreshSelectedTab();
    }
/**
 * Creates the main tab with Observed, Command Center, and Schema panels.
 *
 * @param api Montoya API instance
 * @param engine InMemoryEngine instance
 */
    public MainTab(MontoyaApi api, InMemoryEngine engine) {
        super(new BorderLayout());
        this.engine = engine;
        this.observedPanel = new ObservedPanel(engine);
        this.repoPanel = new RepoPanel(engine, api);
        this.schemaPanel = new SchemaPanel(engine, api);

        tabs = new JTabbedPane();
        tabs.addTab("Observed Params", observedPanel);
        tabs.addTab("Command Center", repoPanel);
        tabs.addTab("Inferred Schema", schemaPanel);
		tabs.addTab("About", createAboutPanel());
        add(tabs, BorderLayout.CENTER);

        Timer refreshTimer = new Timer(5000, e -> refreshSelectedTab());
        refreshTimer.start();

        tabs.addChangeListener(e -> refreshSelectedTab());

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton reloadRepo = new JButton("Reload Repo");
        reloadRepo.addActionListener(e -> {
            engine.reloadRepo();
            refreshSelectedTab();
        });

        JButton clearSession = new JButton("Clear Session");
        clearSession.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                this,
                "Clear observed session data only?",
                "Confirm",
                JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                engine.clearSession();
                refreshSelectedTab();
            }
        });

        controls.add(reloadRepo);
        controls.add(clearSession);
        add(controls, BorderLayout.NORTH);

        refreshSelectedTab();
    }

    private void refreshSelectedTab() {
        Component selected = tabs.getSelectedComponent();
          if (selected instanceof RepoPanel) {
            ((RepoPanel) selected).refresh();
        } else if (selected instanceof ObservedPanel) {
            ((ObservedPanel) selected).refresh();
        } else if (selected instanceof SchemaPanel) {
            ((SchemaPanel) selected).refreshSchema();
        }
    }
	/**
 * Creates the About tab
 */
private JPanel createAboutPanel() {
    JPanel aboutPanel = new JPanel(new BorderLayout());
    aboutPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
    aboutPanel.setBackground(new Color(0x1E1E1E));

    JTextPane aboutText = new JTextPane();
    aboutText.setContentType("text/html");
    aboutText.setEditable(false);
    aboutText.setBackground(new Color(0x1E1E1E));
    aboutText.setForeground(new Color(0xE0E0E0));
    aboutText.setCaretColor(new Color(0xE0E0E0));

    String html = """
        <html>
        <body style='font-family: Segoe UI, Arial; color: #E0E0E0; text-align: center; line-height: 1.5; background-color: #1E1E1E;'>
            <h1 style='color: #00CCFF; font-size: 26px; margin: 15px 0 5px 0;'>HarQL</h1>
            <h2 style='color: #AAAAAA; font-size: 16px; margin: 0 0 20px 0;'>In-Memory GraphQL Harvester</h2>
            <p style='color: #00CCFF; font-size: 14px;'><b>Version 1.0.0</b></p>
           
            <hr style='border: 0; border-top: 1px solid #333333; width: 80%; margin: 20px auto;'>
           
            <p style='font-size: 15px; max-width: 500px; margin: 0 auto 25px auto;'>
                Advanced GraphQL harvesting extension that works without introspection.<br>
                Built for speed, stealth, and deep variable extraction in production environments.
            </p>
           
            <h3 style='color: #00CCFF; font-size: 18px; margin: 20px 0 10px 0;'>Developer</h3>
            <p style='font-size: 15px; margin: 0 0 15px 0;'>
                <b>Hasan Habeeb</b><br>
                Offensive Cybersecurity Researcher<br>
                Syria - Lattakia
            </p>
           
            <h3 style='color: #00CCFF; font-size: 18px; margin: 20px 0 10px 0;'>Contact</h3>
            <p style='font-size: 14px; margin: 5px 0;'>
                <a href='mailto:Xvisor03@gmail.com' style='color: #00CCFF; text-decoration: none;'>Xvisor03@gmail.com</a><br>
                <a href='https://www.linkedin.com/in/hasanhabeeb' style='color: #00CCFF; text-decoration: none;'>LinkedIn: Hasan Habeeb</a><br>
                <a href='https://github.com/Hasnhab' style='color: #00CCFF; text-decoration: none;'>GitHub: @Hasnhab</a>
            </p>
           
            <hr style='border: 0; border-top: 1px solid #333333; width: 80%; margin: 30px auto;'>
           
            <p style='color: #777777; font-size: 12px; margin: 0;'>
                © 2026 Hasan Habeeb. Licensed under MIT.<br>
                Made with passion for the bug bounty & pentest community.
            </p>
        </body>
        </html>
        """;
    aboutText.setText(html);

    aboutText.addHyperlinkListener(e -> {
        if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
            try {
                Desktop.getDesktop().browse(e.getURL().toURI());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Failed to open link: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    });

    JScrollPane scrollPane = new JScrollPane(aboutText);
    scrollPane.setBorder(null);

    aboutPanel.add(scrollPane, BorderLayout.CENTER);

    return aboutPanel;
 }
}
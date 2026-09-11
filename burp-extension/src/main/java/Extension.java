import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;

import java.io.File;
import java.io.IOException;

import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;


public class Extension implements BurpExtension {

    private static final String EXTENSION_NAME =
        "VAPT Sanitizer";

    private static final String PREVIEW_HEADER =
        "VAPT_SANITIZER_PREVIEW_V1";

    private static final String AI_HANDOFF_HEADER =
        "VAPT_AI_HANDOFF_V1";

    private static final String PREF_SELECTED_POLICY =
        "vapt_sanitizer.selected_policy";

    private volatile PolicyMode selectedPolicy =
        PolicyMode.DEFAULT;

    /*
     * Client engagement selection is intentionally session-scoped.
     * It is NOT persisted in Burp preferences, which are global to
     * the extension and could cause accidental cross-client reuse.
     */
    private volatile String selectedEngagement =
        null;

    private JComboBox<PolicyMode> policyCombo;

    private JComboBox<String> engagementCombo;
    private JLabel engagementStatusLabel;

    private JComboBox<LLMTask> taskCombo;
    private JTextArea llmQuestionArea;
    private JLabel llmStatusLabel;

    private JLabel pythonStatusLabel;
    private JLabel sanitizerStatusLabel;
    private JLabel policyStatusLabel;
    private JLabel runtimeMessageLabel;

    private JTextArea gateRulesArea;

    private boolean syncingPolicyCombo =
        false;

    private boolean syncingEngagementCombo =
        false;


    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName(
            EXTENSION_NAME
        );

        selectedPolicy =
            loadPersistedPolicy(
                api
            );

        registerContextMenu(
            api
        );

        JPanel mainTab =
            buildMainTab(
                api
            );

        api.userInterface()
            .applyThemeToComponent(
                mainTab
            );

        api.userInterface()
            .registerSuiteTab(
                EXTENSION_NAME,
                mainTab
            );

        refreshRuntimeStatus(
            api
        );

        api.logging().logToOutput(
            EXTENSION_NAME
            + " initialized. Active policy: "
            + selectedPolicy.displayName
            + ". Engagement: stateless"
        );
    }


    private void registerContextMenu(
        MontoyaApi api
    ) {

        api.userInterface()
            .registerContextMenuItemsProvider(
                new ContextMenuItemsProvider() {

                    @Override
                    public List<Component> provideMenuItems(
                        ContextMenuEvent event
                    ) {

                        Optional<HttpRequestResponse>
                            requestResponse =
                                resolveRequestResponse(
                                    event
                                );

                        if (
                            requestResponse.isEmpty()
                        ) {

                            return List.of();
                        }

                        HttpRequestResponse message =
                            requestResponse.get();

                        JMenu menu =
                            new JMenu(
                                "VAPT Sanitizer"
                            );


                        JMenuItem engagementIndicator =
                            new JMenuItem(
                                "Engagement: "
                                + (
                                    selectedEngagement == null
                                        ? "Stateless"
                                        : selectedEngagement
                                )
                            );

                        engagementIndicator.setEnabled(
                            false
                        );

                        menu.add(
                            engagementIndicator
                        );

                        menu.addSeparator();


                        JMenuItem sanitizeRequest =
                            new JMenuItem(
                                "Sanitize request → preview"
                            );

                        sanitizeRequest
                            .addActionListener(
                                ignored ->
                                    sanitize(
                                        api,
                                        message.request()
                                            .toString(),
                                        "request",
                                        selectedPolicy
                                    )
                            );

                        menu.add(
                            sanitizeRequest
                        );


                        if (
                            message.response()
                                != null
                        ) {

                            JMenuItem sanitizeResponse =
                                new JMenuItem(
                                    "Sanitize response → preview"
                                );

                            sanitizeResponse
                                .addActionListener(
                                    ignored ->
                                        sanitize(
                                            api,
                                            message.response()
                                                .toString(),
                                            "response",
                                            selectedPolicy
                                        )
                                );

                            menu.add(
                                sanitizeResponse
                            );
                        }


                        Optional<
                            MessageEditorHttpRequestResponse
                        > editor =
                            event.messageEditorRequestResponse();

                        if (
                            editor.isPresent()
                        ) {

                            MessageEditorHttpRequestResponse
                                editorContext =
                                    editor.get();

                            Optional<Range> offsets =
                                editorContext
                                    .selectionOffsets();

                            if (
                                offsets.isPresent()
                                &&
                                offsets.get()
                                    .startIndexInclusive()
                                    <
                                offsets.get()
                                    .endIndexExclusive()
                            ) {

                                JMenuItem sanitizeSelection =
                                    new JMenuItem(
                                        "Sanitize selection → preview"
                                    );

                                sanitizeSelection
                                    .addActionListener(
                                        ignored ->
                                            sanitizeSelection(
                                                api,
                                                editorContext
                                            )
                                    );

                                menu.addSeparator();

                                menu.add(
                                    sanitizeSelection
                                );
                            }
                        }


                        menu.addSeparator();

                        JMenu policyMenu =
                            new JMenu(
                                "Policy"
                            );

                        ButtonGroup group =
                            new ButtonGroup();

                        for (
                            PolicyMode mode
                            : PolicyMode.values()
                        ) {

                            JRadioButtonMenuItem item =
                                new JRadioButtonMenuItem(
                                    mode.displayName,
                                    selectedPolicy
                                        == mode
                                );

                            item.addActionListener(
                                ignored ->
                                    setSelectedPolicy(
                                        api,
                                        mode
                                    )
                            );

                            group.add(
                                item
                            );

                            policyMenu.add(
                                item
                            );
                        }

                        menu.add(
                            policyMenu
                        );

                        return List.of(
                            menu
                        );
                    }
                }
            );
    }


    private JPanel buildMainTab(
        MontoyaApi api
    ) {

        JPanel root =
            new JPanel(
                new BorderLayout(
                    14,
                    14
                )
            );

        root.setBorder(
            BorderFactory.createEmptyBorder(
                18,
                18,
                18,
                18
            )
        );


        JPanel header =
            new JPanel(
                new BorderLayout(
                    4,
                    4
                )
            );

        JLabel title =
            new JLabel(
                "VAPT Sanitizer"
            );

        title.setFont(
            title.getFont()
                .deriveFont(
                    Font.BOLD,
                    title.getFont()
                        .getSize2D()
                        + 4.0f
                )
        );

        JLabel subtitle =
            new JLabel(
                "Local security gateway between Burp Suite and external AI workflows."
            );

        header.add(
            title,
            BorderLayout.NORTH
        );

        header.add(
            subtitle,
            BorderLayout.SOUTH
        );

        root.add(
            header,
            BorderLayout.NORTH
        );


        JPanel center =
            new JPanel(
                new GridBagLayout()
            );

        GridBagConstraints gbc =
            new GridBagConstraints();

        gbc.gridx =
            0;

        gbc.gridy =
            0;

        gbc.weightx =
            1.0;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;

        gbc.anchor =
            GridBagConstraints.NORTHWEST;

        gbc.insets =
            new Insets(
                0,
                0,
                12,
                0
            );


        JPanel policyPanel =
            buildPolicyPanel(
                api
            );

        center.add(
            policyPanel,
            gbc
        );


        gbc.gridy++;

        JPanel engagementPanel =
            buildEngagementPanel(
                api
            );

        center.add(
            engagementPanel,
            gbc
        );


        gbc.gridy++;

        JPanel gatePanel =
            buildGatePanel();

        center.add(
            gatePanel,
            gbc
        );


        gbc.gridy++;

        JPanel llmPanel =
            buildLlmPanel();

        center.add(
            llmPanel,
            gbc
        );


        gbc.gridy++;

        gbc.weighty =
            1.0;

        gbc.fill =
            GridBagConstraints.BOTH;

        JPanel runtimePanel =
            buildRuntimePanel(
                api
            );

        center.add(
            runtimePanel,
            gbc
        );


        root.add(
            center,
            BorderLayout.CENTER
        );


        JLabel footer =
            new JLabel(
                "Flow: Burp → Sanitizer → Security Gate → Preview → AI-ready clipboard → Browser"
            );

        root.add(
            footer,
            BorderLayout.SOUTH
        );


        updatePolicyUi(
            selectedPolicy
        );

        return root;
    }


    private JPanel buildPolicyPanel(
        MontoyaApi api
    ) {

        JPanel panel =
            new JPanel(
                new GridBagLayout()
            );

        panel.setBorder(
            BorderFactory.createTitledBorder(
                "Policy"
            )
        );


        GridBagConstraints gbc =
            new GridBagConstraints();

        gbc.insets =
            new Insets(
                6,
                8,
                6,
                8
            );

        gbc.anchor =
            GridBagConstraints.WEST;


        gbc.gridx =
            0;

        gbc.gridy =
            0;

        panel.add(
            new JLabel(
                "Active policy:"
            ),
            gbc
        );


        policyCombo =
            new JComboBox<>(
                PolicyMode.values()
            );

        policyCombo.setSelectedItem(
            selectedPolicy
        );

        policyCombo.addActionListener(
            ignored -> {

                if (
                    syncingPolicyCombo
                ) {

                    return;
                }

                PolicyMode mode =
                    (PolicyMode)
                        policyCombo
                            .getSelectedItem();

                if (
                    mode != null
                ) {

                    setSelectedPolicy(
                        api,
                        mode
                    );
                }
            }
        );


        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;

        panel.add(
            policyCombo,
            gbc
        );


        JLabel hint =
            new JLabel(
                "The selection is persisted across Burp restarts."
            );

        gbc.gridx =
            0;

        gbc.gridy =
            1;

        gbc.gridwidth =
            2;

        gbc.weightx =
            1.0;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;

        panel.add(
            hint,
            gbc
        );


        return panel;
    }


    private JPanel buildEngagementPanel(
        MontoyaApi api
    ) {

        JPanel panel =
            new JPanel(
                new GridBagLayout()
            );

        panel.setBorder(
            BorderFactory.createTitledBorder(
                "Engagement Mapping Vault"
            )
        );


        GridBagConstraints gbc =
            new GridBagConstraints();

        gbc.insets =
            new Insets(
                5,
                8,
                5,
                8
            );

        gbc.anchor =
            GridBagConstraints.WEST;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;


        gbc.gridx =
            0;

        gbc.gridy =
            0;

        gbc.weightx =
            0.0;

        panel.add(
            new JLabel(
                "Active engagement:"
            ),
            gbc
        );


        engagementCombo =
            new JComboBox<>();

        engagementCombo.setPrototypeDisplayValue(
            "CLIENT-ENGAGEMENT-2026-EXAMPLE"
        );


        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        panel.add(
            engagementCombo,
            gbc
        );


        JButton refreshButton =
            new JButton(
                "Refresh"
            );

        refreshButton.addActionListener(
            ignored ->
                refreshEngagementCombo(
                    api
                )
        );


        gbc.gridx =
            2;

        gbc.weightx =
            0.0;

        panel.add(
            refreshButton,
            gbc
        );


        engagementStatusLabel =
            new JLabel();


        gbc.gridx =
            0;

        gbc.gridy =
            1;

        gbc.gridwidth =
            3;

        gbc.weightx =
            1.0;

        panel.add(
            engagementStatusLabel,
            gbc
        );


        refreshEngagementCombo(
            api
        );


        engagementCombo.addActionListener(
            ignored -> {

                if (
                    syncingEngagementCombo
                ) {

                    return;
                }


                Object selected =
                    engagementCombo
                        .getSelectedItem();


                String engagementId =
                    (
                        selected == null
                        ||
                        STATELESS_ENGAGEMENT.equals(
                            selected.toString()
                        )
                    )
                        ? null
                        : selected.toString();


                setSelectedEngagement(
                    api,
                    engagementId
                );
            }
        );


        updateEngagementUi();

        return panel;
    }


    private static final String STATELESS_ENGAGEMENT =
        "(None - stateless)";


    private void refreshEngagementCombo(
        MontoyaApi api
    ) {

        if (
            engagementCombo == null
        ) {

            return;
        }


        List<String> engagementIds =
            availableEngagementIds();


        String preferred =
            selectedEngagement;


        syncingEngagementCombo =
            true;

        try {

            engagementCombo.removeAllItems();

            engagementCombo.addItem(
                STATELESS_ENGAGEMENT
            );


            for (
                String engagementId
                : engagementIds
            ) {

                engagementCombo.addItem(
                    engagementId
                );
            }


            if (
                preferred != null
                &&
                engagementIds.contains(
                    preferred
                )
            ) {

                engagementCombo.setSelectedItem(
                    preferred
                );

            } else {

                if (
                    preferred != null
                ) {

                    api.logging().logToError(
                        "Selected engagement is no longer available: "
                        + preferred
                        + ". Falling back to stateless mode."
                    );
                }


                selectedEngagement =
                    null;

                engagementCombo.setSelectedItem(
                    STATELESS_ENGAGEMENT
                );
            }

        } finally {

            syncingEngagementCombo =
                false;
        }


        updateEngagementUi();
    }


    private List<String> availableEngagementIds() {

        List<String> engagementIds =
            new ArrayList<>();


        File root =
            engagementsRoot();


        File[] directories =
            root.listFiles(
                file ->
                    file.isDirectory()
                    &&
                    isValidEngagementId(
                        file.getName()
                    )
                    &&
                    new File(
                        file,
                        "mapping.enc"
                    ).isFile()
            );


        if (
            directories == null
        ) {

            return engagementIds;
        }


        for (
            File directory
            : directories
        ) {

            engagementIds.add(
                directory.getName()
            );
        }


        engagementIds.sort(
            String.CASE_INSENSITIVE_ORDER
        );


        return engagementIds;
    }


    private File sanitizerDataRoot() {

        String explicit =
            System.getenv(
                "VAPT_SANITIZE_DATA_DIR"
            );

        if (
            explicit != null
            &&
            !explicit.isBlank()
        ) {
            return new File(
                explicit
            );
        }


        String xdg =
            System.getenv(
                "XDG_DATA_HOME"
            );

        if (
            xdg != null
            &&
            !xdg.isBlank()
        ) {
            return new File(
                xdg,
                "vapt-sanitize"
            );
        }


        return new File(
            System.getProperty(
                "user.home"
            ),
            ".local/share/vapt-sanitize"
        );
    }


    private File sanitizerConfigRoot() {

        String explicit =
            System.getenv(
                "VAPT_SANITIZE_CONFIG_DIR"
            );

        if (
            explicit != null
            &&
            !explicit.isBlank()
        ) {
            return new File(
                explicit
            );
        }


        String xdg =
            System.getenv(
                "XDG_CONFIG_HOME"
            );

        if (
            xdg != null
            &&
            !xdg.isBlank()
        ) {
            return new File(
                xdg,
                "vapt-sanitize"
            );
        }


        return new File(
            System.getProperty(
                "user.home"
            ),
            ".config/vapt-sanitize"
        );
    }


    private File engagementsRoot() {

        return new File(
            sanitizerDataRoot(),
            "engagements"
        );
    }


    private boolean isValidEngagementId(
        String engagementId
    ) {

        return (
            engagementId != null
            &&
            engagementId.matches(
                "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
            )
        );
    }


    private boolean engagementExists(
        String engagementId
    ) {

        if (
            !isValidEngagementId(
                engagementId
            )
        ) {

            return false;
        }


        File directory =
            new File(
                engagementsRoot(),
                engagementId
            );


        return (
            directory.isDirectory()
            &&
            new File(
                directory,
                "mapping.enc"
            ).isFile()
        );
    }


    private void setSelectedEngagement(
        MontoyaApi api,
        String engagementId
    ) {

        String normalized =
            (
                engagementId == null
                ||
                engagementId.isBlank()
            )
                ? null
                : engagementId.trim();


        if (
            normalized != null
            &&
            !engagementExists(
                normalized
            )
        ) {

            showError(
                "VAPT Sanitizer",
                (
                    "Engagement is no longer available:\n\n"
                    + normalized
                )
            );

            refreshEngagementCombo(
                api
            );

            return;
        }


        selectedEngagement =
            normalized;


        api.logging().logToOutput(
            "VAPT Sanitizer engagement for this Burp session: "
            + (
                normalized == null
                    ? "stateless"
                    : normalized
            )
        );


        updateEngagementUi();
    }


    private void updateEngagementUi() {

        if (
            engagementStatusLabel == null
        ) {

            return;
        }


        if (
            selectedEngagement == null
        ) {

            engagementStatusLabel.setText(
                "Stateless mode: mappings are not shared with CLI or other Burp messages. "
                + "Select an engagement before client work."
            );

        } else {

            engagementStatusLabel.setText(
                "Encrypted mapping active for this Burp session: "
                + selectedEngagement
                + ". Real values stay local; redacted secrets are never stored."
            );
        }
    }


    private JPanel buildGatePanel() {

        JPanel panel =
            new JPanel(
                new BorderLayout(
                    8,
                    8
                )
            );

        panel.setBorder(
            BorderFactory.createTitledBorder(
                "Security Gate"
            )
        );


        gateRulesArea =
            new JTextArea(
                4,
                40
            );

        gateRulesArea.setEditable(
            false
        );

        gateRulesArea.setLineWrap(
            false
        );

        gateRulesArea.setFont(
            new Font(
                Font.MONOSPACED,
                Font.PLAIN,
                13
            )
        );


        panel.add(
            new JScrollPane(
                gateRulesArea
            ),
            BorderLayout.CENTER
        );


        return panel;
    }


    private JPanel buildLlmPanel() {

        JPanel panel =
            new JPanel(
                new GridBagLayout()
            );

        panel.setBorder(
            BorderFactory.createTitledBorder(
                "AI Handoff"
            )
        );


        GridBagConstraints gbc =
            new GridBagConstraints();

        gbc.insets =
            new Insets(
                5,
                8,
                5,
                8
            );

        gbc.anchor =
            GridBagConstraints.WEST;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;


        gbc.gridx =
            0;

        gbc.gridy =
            0;

        gbc.weightx =
            0.0;

        panel.add(
            new JLabel(
                "Task:"
            ),
            gbc
        );


        taskCombo =
            new JComboBox<>(
                LLMTask.values()
            );

        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        panel.add(
            taskCombo,
            gbc
        );


        gbc.gridx =
            0;

        gbc.gridy =
            1;

        gbc.weightx =
            0.0;

        gbc.anchor =
            GridBagConstraints.NORTHWEST;

        panel.add(
            new JLabel(
                "Question:"
            ),
            gbc
        );


        llmQuestionArea =
            new JTextArea(
                3,
                40
            );

        llmQuestionArea.setLineWrap(
            true
        );

        llmQuestionArea.setWrapStyleWord(
            true
        );

        JScrollPane questionScroll =
            new JScrollPane(
                llmQuestionArea
            );

        questionScroll.setPreferredSize(
            new Dimension(
                500,
                80
            )
        );

        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        gbc.fill =
            GridBagConstraints.BOTH;

        panel.add(
            questionScroll,
            gbc
        );


        gbc.gridx =
            0;

        gbc.gridy =
            2;

        gbc.weightx =
            0.0;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;

        panel.add(
            new JLabel(
                "Destination:"
            ),
            gbc
        );


        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        panel.add(
            new JLabel(
                "Clipboard → browser (manual paste)"
            ),
            gbc
        );


        llmStatusLabel =
            new JLabel(
                "No network communication. "
                + "VAPT Sanitizer only prepares and copies the AI-ready prompt."
            );

        gbc.gridx =
            0;

        gbc.gridy =
            3;

        gbc.gridwidth =
            2;

        gbc.weightx =
            1.0;

        panel.add(
            llmStatusLabel,
            gbc
        );


        taskCombo.addActionListener(
            ignored ->
                updateLlmUi()
        );


        updateLlmUi();

        return panel;
    }


    private void updateLlmUi() {

        if (
            taskCombo == null
            || llmQuestionArea == null
            || llmStatusLabel == null
        ) {

            return;
        }


        LLMTask task =
            (LLMTask)
                taskCombo
                    .getSelectedItem();


        boolean custom =
            task
                == LLMTask.CUSTOM;


        llmQuestionArea.setToolTipText(
            custom
                ? "Required for Custom question."
                : "Optional analyst question appended to the selected task."
        );


        llmStatusLabel.setText(
            custom
                ? (
                    "Custom question selected. "
                    + "The Question field is required. "
                    + "No network communication."
                )
                : (
                    "AI-ready prompt will be copied to the clipboard only. "
                    + "Paste it manually into ChatGPT, Claude, Gemini, "
                    + "or another AI in your browser."
                )
        );
    }


    private JPanel buildRuntimePanel(
        MontoyaApi api
    ) {

        JPanel panel =
            new JPanel(
                new GridBagLayout()
            );

        panel.setBorder(
            BorderFactory.createTitledBorder(
                "Runtime"
            )
        );


        GridBagConstraints gbc =
            new GridBagConstraints();

        gbc.insets =
            new Insets(
                5,
                8,
                5,
                8
            );

        gbc.anchor =
            GridBagConstraints.WEST;

        gbc.fill =
            GridBagConstraints.HORIZONTAL;


        pythonStatusLabel =
            new JLabel(
                "Checking..."
            );

        sanitizerStatusLabel =
            new JLabel(
                "Checking..."
            );

        policyStatusLabel =
            new JLabel(
                "Checking..."
            );

        runtimeMessageLabel =
            new JLabel(
                "Runtime check pending."
            );


        addRuntimeRow(
            panel,
            gbc,
            0,
            "Python",
            pythonStatusLabel
        );

        addRuntimeRow(
            panel,
            gbc,
            1,
            "Sanitizer",
            sanitizerStatusLabel
        );

        addRuntimeRow(
            panel,
            gbc,
            2,
            "Policy",
            policyStatusLabel
        );


        JButton refreshButton =
            new JButton(
                "Refresh runtime"
            );

        refreshButton.addActionListener(
            ignored ->
                refreshRuntimeStatus(
                    api
                )
        );


        gbc.gridx =
            0;

        gbc.gridy =
            3;

        gbc.gridwidth =
            1;

        gbc.weightx =
            0.0;

        panel.add(
            refreshButton,
            gbc
        );


        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        panel.add(
            runtimeMessageLabel,
            gbc
        );


        return panel;
    }


    private void addRuntimeRow(
        JPanel panel,
        GridBagConstraints gbc,
        int row,
        String name,
        JLabel status
    ) {

        gbc.gridx =
            0;

        gbc.gridy =
            row;

        gbc.gridwidth =
            1;

        gbc.weightx =
            0.0;

        panel.add(
            new JLabel(
                name + ":"
            ),
            gbc
        );


        gbc.gridx =
            1;

        gbc.weightx =
            1.0;

        panel.add(
            status,
            gbc
        );
    }


    private PolicyMode loadPersistedPolicy(
        MontoyaApi api
    ) {

        try {

            String value =
                api.persistence()
                    .preferences()
                    .getString(
                        PREF_SELECTED_POLICY
                    );

            if (
                value == null
                || value.isBlank()
            ) {

                return PolicyMode.DEFAULT;
            }

            return PolicyMode.valueOf(
                value
            );

        } catch (
            IllegalArgumentException exc
        ) {

            api.logging().logToError(
                "Invalid persisted VAPT Sanitizer policy. "
                + "Falling back to Default."
            );

            return PolicyMode.DEFAULT;
        }
    }


    private void setSelectedPolicy(
        MontoyaApi api,
        PolicyMode mode
    ) {

        selectedPolicy =
            mode;

        api.persistence()
            .preferences()
            .setString(
                PREF_SELECTED_POLICY,
                mode.name()
            );

        api.logging().logToOutput(
            "VAPT Sanitizer policy: "
            + mode.displayName
        );


        SwingUtilities.invokeLater(
            () -> {

                if (
                    policyCombo != null
                ) {

                    syncingPolicyCombo =
                        true;

                    try {

                        policyCombo
                            .setSelectedItem(
                                mode
                            );

                    } finally {

                        syncingPolicyCombo =
                            false;
                    }
                }

                updatePolicyUi(
                    mode
                );

                refreshRuntimeStatus(
                    api
                );
            }
        );
    }


    private void updatePolicyUi(
        PolicyMode mode
    ) {

        if (
            gateRulesArea == null
        ) {

            return;
        }

        gateRulesArea.setText(
            "Loading gate rules for "
            + mode.displayName
            + "..."
        );
    }


    private void refreshRuntimeStatus(
        MontoyaApi api
    ) {

        if (
            pythonStatusLabel == null
            || sanitizerStatusLabel == null
            || policyStatusLabel == null
        ) {

            return;
        }


        SwingUtilities.invokeLater(
            () -> {

                pythonStatusLabel.setText(
                    "Checking..."
                );

                sanitizerStatusLabel.setText(
                    "Checking..."
                );

                policyStatusLabel.setText(
                    "Checking..."
                );

                runtimeMessageLabel.setText(
                    "Running local self-check..."
                );
            }
        );


        PolicyMode policySnapshot =
            selectedPolicy;


        Thread worker =
            new Thread(
                () -> {

                    String home =
                        sanitizerHome();

                    String python =
                        sanitizerPython(
                            home
                        );

                    File pythonFile =
                        new File(
                            python
                        );

                    File sanitizerFile =
                        new File(
                            home,
                            "vapt_sanitize/integrations/burp.py"
                        );

                    File policyFile =
                        policySnapshot.relativePath
                            == null
                            ? null
                            : new File(
                                home,
                                policySnapshot.relativePath
                            );


                    boolean pythonExists =
                        pythonFile.isFile();

                    boolean sanitizerExists =
                        sanitizerFile.isFile();

                    boolean policyExists =
                        policyFile == null
                        || policyFile.isFile();


                    RuntimeProbe probe =
                        null;

                    String probeError =
                        null;


                    if (
                        pythonExists
                        && sanitizerExists
                        && policyExists
                    ) {

                        try {

                            probe =
                                runRuntimeProbe(
                                    home,
                                    python,
                                    policyFile
                                );

                        } catch (
                            Exception exc
                        ) {

                            probeError =
                                safeMessage(
                                    exc
                                );
                        }
                    }


                    RuntimeProbe finalProbe =
                        probe;

                    String finalProbeError =
                        probeError;


                    SwingUtilities.invokeLater(
                        () -> {

                            pythonStatusLabel.setText(
                                pythonExists
                                    ? "✓ "
                                        + python
                                    : "✗ "
                                        + python
                            );

                            sanitizerStatusLabel.setText(
                                sanitizerExists
                                    ? "✓ "
                                        + sanitizerFile
                                            .getAbsolutePath()
                                    : "✗ "
                                        + sanitizerFile
                                            .getAbsolutePath()
                            );

                            if (
                                policyFile == null
                            ) {

                                policyStatusLabel.setText(
                                    "✓ Built-in Default policy"
                                );

                            } else {

                                policyStatusLabel.setText(
                                    policyExists
                                        ? "✓ "
                                            + policyFile
                                                .getAbsolutePath()
                                        : "✗ "
                                            + policyFile
                                                .getAbsolutePath()
                                );
                            }


                            if (
                                finalProbe != null
                            ) {

                                gateRulesArea.setText(
                                    "PRESERVED_FINDING : "
                                    + finalProbe
                                        .preservedFinding
                                    + "\n"
                                    + "NO_FINDINGS       : "
                                    + finalProbe
                                        .noFindings
                                    + "\n"
                                    + "MANDATORY SECRET  : BLOCKED"
                                    + "\n"
                                    + "RESIDUAL SECRET   : BLOCKED"
                                );

                                runtimeMessageLabel.setText(
                                    "✓ Python import, policy load "
                                    + "and sanitizer bridge verified."
                                );

                            } else {

                                gateRulesArea.setText(
                                    "Gate rules unavailable "
                                    + "until runtime validation succeeds."
                                );

                                runtimeMessageLabel.setText(
                                    "✗ "
                                    + (
                                        finalProbeError
                                            == null
                                            ? "Runtime prerequisites missing."
                                            : finalProbeError
                                    )
                                );
                            }
                        }
                    );
                },
                "vapt-sanitizer-runtime-check"
            );


        worker.setDaemon(
            true
        );

        worker.start();
    }


    private RuntimeProbe runRuntimeProbe(
        String home,
        String python,
        File policyFile
    ) throws Exception {

        String script =
            "from vapt_sanitize.policy import Policy\n"
            + "import vapt_sanitize.integrations.burp\n"
            + "import sys\n"
            + "p = Policy.from_file(sys.argv[1]) "
            + "if len(sys.argv) > 1 else Policy()\n"
            + "print('PRESERVED=' + "
            + "p.gate_state('PRESERVED_FINDING'))\n"
            + "print('NO_FINDINGS=' + "
            + "p.gate_state('NO_FINDINGS'))\n";


        List<String> command =
            new ArrayList<>();

        command.add(
            python
        );

        command.add(
            "-c"
        );

        command.add(
            script
        );

        if (
            policyFile != null
        ) {

            command.add(
                policyFile.getAbsolutePath()
            );
        }


        ProcessBuilder builder =
            new ProcessBuilder(
                command
            );

        builder.directory(
            new File(
                home
            )
        );

        builder.redirectErrorStream(
            true
        );


        Process process =
            builder.start();


        boolean finished =
            process.waitFor(
                5,
                TimeUnit.SECONDS
            );


        if (
            !finished
        ) {

            process.destroyForcibly();

            throw new IllegalStateException(
                "Runtime self-check timeout."
            );
        }


        String output =
            new String(
                process.getInputStream()
                    .readAllBytes(),
                StandardCharsets.UTF_8
            ).trim();


        if (
            process.exitValue()
                != 0
        ) {

            throw new IllegalStateException(
                output.isEmpty()
                    ? "Runtime self-check failed."
                    : output
            );
        }


        String preserved =
            null;

        String noFindings =
            null;


        for (
            String line
            : output.split("\\R")
        ) {

            if (
                line.startsWith(
                    "PRESERVED="
                )
            ) {

                preserved =
                    line.substring(
                        "PRESERVED="
                            .length()
                    ).trim();

            } else if (
                line.startsWith(
                    "NO_FINDINGS="
                )
            ) {

                noFindings =
                    line.substring(
                        "NO_FINDINGS="
                            .length()
                    ).trim();
            }
        }


        if (
            preserved == null
            || noFindings == null
        ) {

            throw new IllegalStateException(
                "Runtime self-check returned invalid policy data."
            );
        }


        return new RuntimeProbe(
            preserved,
            noFindings
        );
    }


    private String sanitizerHome() {

        String home =
            System.getenv(
                "VAPT_SANITIZE_HOME"
            );

        if (
            home == null
            || home.isBlank()
        ) {

            home =
                System.getProperty(
                    "user.home"
                )
                + "/vapt-sanitize";
        }

        return home;
    }


    private String sanitizerPython(
        String home
    ) {

        String python =
            System.getenv(
                "VAPT_SANITIZE_PYTHON"
            );

        if (
            python == null
            || python.isBlank()
        ) {

            python =
                home
                + "/.venv/bin/python";
        }

        return python;
    }


    private Optional<HttpRequestResponse>
    resolveRequestResponse(
        ContextMenuEvent event
    ) {

        Optional<
            MessageEditorHttpRequestResponse
        > editor =
            event.messageEditorRequestResponse();

        if (
            editor.isPresent()
        ) {

            return Optional.of(
                editor.get()
                    .requestResponse()
            );
        }

        List<HttpRequestResponse> selected =
            event.selectedRequestResponses();

        if (
            selected.isEmpty()
        ) {

            return Optional.empty();
        }

        return Optional.of(
            selected.get(
                0
            )
        );
    }


    private void sanitizeSelection(
        MontoyaApi api,
        MessageEditorHttpRequestResponse editor
    ) {

        Optional<Range> offsets =
            editor.selectionOffsets();

        if (
            offsets.isEmpty()
        ) {

            showError(
                "VAPT Sanitizer",
                "No text is selected."
            );

            return;
        }


        Range range =
            offsets.get();

        int start =
            range.startIndexInclusive();

        int end =
            range.endIndexExclusive();

        String source;


        if (
            editor.selectionContext()
                ==
            MessageEditorHttpRequestResponse
                .SelectionContext.REQUEST
        ) {

            source =
                editor.requestResponse()
                    .request()
                    .toString();

        } else {

            if (
                editor.requestResponse()
                    .response()
                    == null
            ) {

                showError(
                    "VAPT Sanitizer",
                    "No response is available."
                );

                return;
            }

            source =
                editor.requestResponse()
                    .response()
                    .toString();
        }


        if (
            start < 0
            || end > source.length()
            || start >= end
        ) {

            showError(
                "VAPT Sanitizer",
                "Invalid selection range."
            );

            return;
        }


        String selectedText =
            source.substring(
                start,
                end
            );


        if (
            selectedText.isEmpty()
        ) {

            showError(
                "VAPT Sanitizer",
                "Selected text is empty."
            );

            return;
        }


        sanitize(
            api,
            selectedText,
            "selection",
            selectedPolicy
        );
    }


    private void sanitize(
        MontoyaApi api,
        String input,
        String type,
        PolicyMode policyMode
    ) {

        PolicyMode policySnapshot =
            policyMode;

        String engagementSnapshot =
            selectedEngagement;


        Thread worker =
            new Thread(
                () -> {

                    try {

                        PreviewResult result =
                            runSanitizerPreview(
                                input,
                                policySnapshot,
                                engagementSnapshot
                            );


                        SwingUtilities.invokeLater(
                            () ->
                                showPreview(
                                    api,
                                    type,
                                    policySnapshot,
                                    result,
                                    engagementSnapshot
                                )
                        );


                    } catch (
                        Exception exc
                    ) {

                        api.logging().logToError(
                            "VAPT Sanitizer failed: "
                            + exc.getClass()
                                .getSimpleName()
                            + ": "
                            + exc.getMessage()
                        );


                        showError(
                            "VAPT Sanitizer",
                            "Sanitization failed:\n\n"
                            + safeMessage(
                                exc
                            )
                        );
                    }
                },
                "vapt-sanitizer-worker"
            );


        worker.setDaemon(
            true
        );

        worker.start();
    }


    private PreviewResult runSanitizerPreview(
        String input,
        PolicyMode policyMode,
        String engagementId
    ) throws Exception {

        String home =
            sanitizerHome();

        String python =
            sanitizerPython(
                home
            );


        List<String> command =
            new ArrayList<>();

        command.add(
            python
        );

        command.add(
            "-m"
        );

        command.add(
            "vapt_sanitize.integrations.burp"
        );

        command.add(
            "--profile"
        );

        command.add(
            "BURP"
        );


        if (
            engagementId != null
            &&
            !engagementId.isBlank()
        ) {

            command.add(
                "--engagement"
            );

            command.add(
                engagementId
            );
        }


        if (
            policyMode.relativePath
                != null
        ) {

            File policyFile =
                new File(
                    home,
                    policyMode.relativePath
                );

            if (
                !policyFile.isFile()
            ) {

                throw new IllegalStateException(
                    "Policy file not found: "
                    + policyFile
                        .getAbsolutePath()
                );
            }


            command.add(
                "--policy"
            );

            command.add(
                policyFile
                    .getAbsolutePath()
            );
        }


        command.add(
            "--preview"
        );


        ProcessBuilder builder =
            new ProcessBuilder(
                command
            );

        builder.directory(
            new File(
                home
            )
        );

        /*
         * Force the Python subprocess to use the exact same vault roots
         * used by the Java UI. Desktop launchers and wrapper scripts can
         * expose HOME/XDG values that differ from an interactive shell.
         * Without explicit roots Burp can list an engagement but Python
         * can still look for mapping.enc/master.key somewhere else.
         */
        builder.environment().put(
            "VAPT_SANITIZE_DATA_DIR",
            sanitizerDataRoot()
                .getAbsolutePath()
        );

        builder.environment().put(
            "VAPT_SANITIZE_CONFIG_DIR",
            sanitizerConfigRoot()
                .getAbsolutePath()
        );


        Process process =
            builder.start();


        process.getOutputStream()
            .write(
                input.getBytes(
                    StandardCharsets.UTF_8
                )
            );

        process.getOutputStream()
            .close();


        boolean finished =
            process.waitFor(
                15,
                TimeUnit.SECONDS
            );


        if (
            !finished
        ) {

            process.destroyForcibly();

            throw new IllegalStateException(
                "Sanitizer process timeout."
            );
        }


        byte[] stdout =
            process.getInputStream()
                .readAllBytes();

        byte[] stderr =
            process.getErrorStream()
                .readAllBytes();


        if (
            process.exitValue()
                != 0
        ) {

            String error =
                new String(
                    stderr,
                    StandardCharsets.UTF_8
                ).trim();


            throw new IllegalStateException(
                error.isEmpty()
                    ? "Sanitizer process failed."
                    : error
            );
        }


        String protocol =
            new String(
                stdout,
                StandardCharsets.UTF_8
            );


        return parsePreviewProtocol(
            protocol
        );
    }


    private PreviewResult parsePreviewProtocol(
        String protocol
    ) {

        String[] lines =
            protocol.split(
                "\\R"
            );


        if (
            lines.length == 0
            || !PREVIEW_HEADER.equals(
                lines[0].trim()
            )
        ) {

            throw new IllegalStateException(
                "Invalid sanitizer preview response."
            );
        }


        String sanitized =
            null;

        int findingsCount =
            -1;

        String securityGate =
            null;

        String securityGateReason =
            null;

        List<FindingSummary> findings =
            new ArrayList<>();

        boolean ended =
            false;


        for (
            int i = 1;
            i < lines.length;
            i++
        ) {

            String line =
                lines[i];


            if (
                line.startsWith(
                    "SANITIZED_B64:"
                )
            ) {

                String encoded =
                    line.substring(
                        "SANITIZED_B64:"
                            .length()
                    );

                sanitized =
                    decodeBase64(
                        encoded
                    );


            } else if (
                line.startsWith(
                    "FINDINGS_COUNT:"
                )
            ) {

                String value =
                    line.substring(
                        "FINDINGS_COUNT:"
                            .length()
                    ).trim();


                try {

                    findingsCount =
                        Integer.parseInt(
                            value
                        );

                } catch (
                    NumberFormatException exc
                ) {

                    throw new IllegalStateException(
                        "Invalid findings count."
                    );
                }


            } else if (
                line.startsWith(
                    "SECURITY_GATE:"
                )
            ) {

                securityGate =
                    line.substring(
                        "SECURITY_GATE:"
                            .length()
                    ).trim();


            } else if (
                line.startsWith(
                    "SECURITY_GATE_REASON:"
                )
            ) {

                String encoded =
                    line.substring(
                        "SECURITY_GATE_REASON:"
                            .length()
                    );

                securityGateReason =
                    decodeBase64(
                        encoded
                    );


            } else if (
                line.startsWith(
                    "FINDING:"
                )
            ) {

                String payload =
                    line.substring(
                        "FINDING:"
                            .length()
                    );


                findings.add(
                    parseFinding(
                        payload
                    )
                );


            } else if (
                line.equals(
                    "END"
                )
            ) {

                ended =
                    true;

                break;
            }
        }


        if (
            !ended
        ) {

            throw new IllegalStateException(
                "Incomplete sanitizer preview response."
            );
        }


        if (
            sanitized == null
            || sanitized.isEmpty()
        ) {

            throw new IllegalStateException(
                "Sanitizer returned empty output."
            );
        }


        if (
            findingsCount < 0
        ) {

            throw new IllegalStateException(
                "Missing findings count."
            );
        }


        if (
            findingsCount
                != findings.size()
        ) {

            throw new IllegalStateException(
                "Finding count mismatch."
            );
        }


        if (
            securityGate == null
            || securityGate.isBlank()
        ) {

            throw new IllegalStateException(
                "Missing security gate."
            );
        }


        if (
            securityGateReason == null
            || securityGateReason.isBlank()
        ) {

            throw new IllegalStateException(
                "Missing security gate reason."
            );
        }


        if (
            !"PASS".equals(
                securityGate
            )
            &&
            !"REVIEW".equals(
                securityGate
            )
            &&
            !"BLOCKED".equals(
                securityGate
            )
        ) {

            throw new IllegalStateException(
                "Unknown security gate state."
            );
        }


        return new PreviewResult(
            sanitized,
            findings,
            securityGate,
            securityGateReason
        );
    }


    private FindingSummary parseFinding(
        String payload
    ) {

        String[] fields =
            payload.split(
                ":",
                -1
            );


        if (
            fields.length
                != 3
        ) {

            throw new IllegalStateException(
                "Invalid finding entry."
            );
        }


        return new FindingSummary(
            decodeBase64(
                fields[0]
            ),
            decodeBase64(
                fields[1]
            ),
            decodeBase64(
                fields[2]
            )
        );
    }


    private String decodeBase64(
        String value
    ) {

        try {

            return new String(
                Base64.getDecoder()
                    .decode(
                        value
                    ),
                StandardCharsets.UTF_8
            );

        } catch (
            IllegalArgumentException exc
        ) {

            throw new IllegalStateException(
                "Invalid preview encoding."
            );
        }
    }


    private void showPreview(
        MontoyaApi api,
        String type,
        PolicyMode policyMode,
        PreviewResult result,
        String engagementId
    ) {

        LLMTask taskSnapshot =
            selectedLlmTask();

        String questionSnapshot =
            selectedLlmQuestion();


        JDialog dialog =
            new JDialog();


        dialog.setTitle(
            "VAPT Sanitizer — Preview"
        );

        dialog.setModal(
            false
        );

        dialog.setDefaultCloseOperation(
            JDialog.DISPOSE_ON_CLOSE
        );


        JPanel root =
            new JPanel(
                new BorderLayout(
                    10,
                    10
                )
            );


        root.setBorder(
            BorderFactory.createEmptyBorder(
                12,
                12,
                12,
                12
            )
        );


        JPanel gatePanel =
            new JPanel(
                new BorderLayout()
            );


        String gateText;

        if (
            "PASS".equals(
                result.securityGate
            )
        ) {

            gateText =
                "✓ SAFE TO SEND";

        } else if (
            "REVIEW".equals(
                result.securityGate
            )
        ) {

            gateText =
                "⚠ REVIEW REQUIRED";

        } else {

            gateText =
                "⛔ BLOCKED";
        }


        JLabel gateLabel =
            new JLabel(
                gateText
                + " — "
                + result.securityGateReason
            );


        gateLabel.setBorder(
            BorderFactory.createEmptyBorder(
                8,
                8,
                8,
                8
            )
        );


        gatePanel.add(
            gateLabel,
            BorderLayout.NORTH
        );


        JPanel summary =
            new JPanel(
                new FlowLayout(
                    FlowLayout.LEFT
                )
            );


        summary.add(
            new JLabel(
                "Input: "
                + type
            )
        );


        summary.add(
            new JLabel(
                "    Policy: "
                + policyMode.displayName
            )
        );


        summary.add(
            new JLabel(
                "    Findings: "
                + result.findings.size()
            )
        );


        summary.add(
            new JLabel(
                "    Engagement: "
                + (
                    engagementId == null
                        ? "Stateless"
                        : engagementId
                )
            )
        );


        summary.add(
            new JLabel(
                "    AI handoff: Clipboard / "
                + taskSnapshot.displayName
            )
        );


        gatePanel.add(
            summary,
            BorderLayout.SOUTH
        );


        root.add(
            gatePanel,
            BorderLayout.NORTH
        );


        StringBuilder findingsText =
            new StringBuilder();


        if (
            result.findings.isEmpty()
        ) {

            findingsText.append(
                "No sensitive findings detected."
            );

        } else {

            for (
                FindingSummary finding
                : result.findings
            ) {

                findingsText
                    .append(
                        finding.category
                    )
                    .append(
                        "   "
                    )
                    .append(
                        finding.action
                    )
                    .append(
                        "   —   "
                    )
                    .append(
                        finding.reason
                    )
                    .append(
                        "\n"
                    );
            }
        }


        JTextArea findingsArea =
            new JTextArea(
                findingsText.toString()
            );


        findingsArea.setEditable(
            false
        );

        findingsArea.setLineWrap(
            true
        );

        findingsArea.setWrapStyleWord(
            true
        );


        JScrollPane findingsScroll =
            new JScrollPane(
                findingsArea
            );


        findingsScroll.setPreferredSize(
            new Dimension(
                760,
                150
            )
        );


        findingsScroll.setBorder(
            BorderFactory.createTitledBorder(
                "Detections"
            )
        );


        JTextArea contentArea =
            new JTextArea(
                result.sanitized
            );


        contentArea.setEditable(
            false
        );

        contentArea.setLineWrap(
            false
        );


        contentArea.setFont(
            new Font(
                Font.MONOSPACED,
                Font.PLAIN,
                13
            )
        );


        JScrollPane contentScroll =
            new JScrollPane(
                contentArea
            );


        contentScroll.setBorder(
            BorderFactory.createTitledBorder(
                "Sanitized content"
            )
        );


        JPanel center =
            new JPanel(
                new BorderLayout(
                    8,
                    8
                )
            );


        center.add(
            findingsScroll,
            BorderLayout.NORTH
        );


        center.add(
            contentScroll,
            BorderLayout.CENTER
        );


        root.add(
            center,
            BorderLayout.CENTER
        );


        JButton cancelButton =
            new JButton(
                "Cancel"
            );


        JButton copyButton =
            new JButton(
                "Copy sanitized"
            );


        JButton copyAiPromptButton =
            new JButton(
                "Copy AI Prompt"
            );


        boolean aiHandoffAllowed =
            !"BLOCKED".equals(
                result.securityGate
            );


        copyAiPromptButton.setEnabled(
            aiHandoffAllowed
        );


        if (
            aiHandoffAllowed
        ) {

            copyAiPromptButton.setToolTipText(
                "Build an AI-ready prompt from sanitized content "
                + "and copy it to the clipboard. No network communication."
            );

        } else {

            copyAiPromptButton.setToolTipText(
                "AI handoff disabled because the Security Gate blocked this output."
            );
        }


        cancelButton.addActionListener(
            ignored ->
                dialog.dispose()
        );


        if (
            "BLOCKED".equals(
                result.securityGate
            )
        ) {

            copyButton.setEnabled(
                false
            );

            copyButton.setToolTipText(
                "Copy disabled because the Security Gate blocked this output."
            );
        }


        copyButton.addActionListener(
            ignored -> {

                if (
                    "BLOCKED".equals(
                        result.securityGate
                    )
                ) {

                    return;
                }


                if (
                    "REVIEW".equals(
                        result.securityGate
                    )
                ) {

                    int choice =
                        JOptionPane.showConfirmDialog(
                            dialog,
                            (
                                "The Security Gate requires manual review.\n\n"
                                + result.securityGateReason
                                + "\n\n"
                                + "Copy the sanitized content anyway?"
                            ),
                            "VAPT Sanitizer — Review Required",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE
                        );


                    if (
                        choice
                            != JOptionPane.YES_OPTION
                    ) {

                        return;
                    }
                }


                try {

                    writeAndVerifyClipboard(
                        result.sanitized
                    );


                    api.logging().logToOutput(
                        "Sanitized "
                        + type
                        + " copied to clipboard "
                        + "using policy "
                        + policyMode.displayName
                        + " with gate "
                        + result.securityGate
                        + "."
                    );


                    dialog.dispose();


                    showInfo(
                        "VAPT Sanitizer",
                        "Sanitized "
                        + type
                        + " copied to clipboard."
                    );


                } catch (
                    Exception exc
                ) {

                    api.logging().logToError(
                        "Clipboard write failed: "
                        + exc.getMessage()
                    );


                    showError(
                        "VAPT Sanitizer",
                        "Clipboard write failed:\n\n"
                        + safeMessage(
                            exc
                        )
                    );
                }
            }
        );


        copyAiPromptButton.addActionListener(
            ignored -> {

                if (
                    "BLOCKED".equals(
                        result.securityGate
                    )
                ) {

                    return;
                }


                if (
                    taskSnapshot
                        == LLMTask.CUSTOM
                    &&
                    (
                        questionSnapshot == null
                        || questionSnapshot.isBlank()
                    )
                ) {

                    showError(
                        "VAPT Sanitizer",
                        "Custom question requires text in the AI Handoff Question field."
                    );

                    return;
                }


                boolean reviewApproved =
                    false;


                if (
                    "REVIEW".equals(
                        result.securityGate
                    )
                ) {

                    int choice =
                        JOptionPane.showConfirmDialog(
                            dialog,
                            (
                                "The Security Gate requires manual review.\n\n"
                                + result.securityGateReason
                                + "\n\n"
                                + "Prepare and copy the AI prompt anyway?"
                            ),
                            "VAPT Sanitizer — Review Required",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE
                        );


                    if (
                        choice
                            != JOptionPane.YES_OPTION
                    ) {

                        return;
                    }


                    reviewApproved =
                        true;
                }


                final boolean approved =
                    reviewApproved;


                copyAiPromptButton.setEnabled(
                    false
                );

                copyAiPromptButton.setText(
                    "Preparing..."
                );


                Thread handoffWorker =
                    new Thread(
                        () -> {

                            try {

                                String aiPrompt =
                                    runAiHandoff(
                                        result.sanitized,
                                        taskSnapshot,
                                        result.securityGate,
                                        approved,
                                        policyMode,
                                        questionSnapshot,
                                        sourceLabelForType(
                                            type
                                        )
                                    );


                                writeAndVerifyClipboard(
                                    aiPrompt
                                );


                                api.logging().logToOutput(
                                    "AI-ready prompt for "
                                    + type
                                    + " copied to clipboard "
                                    + "using policy "
                                    + policyMode.displayName
                                    + " with gate "
                                    + result.securityGate
                                    + "."
                                );


                                SwingUtilities.invokeLater(
                                    () -> {

                                        copyAiPromptButton.setText(
                                            "Copy AI Prompt"
                                        );

                                        copyAiPromptButton.setEnabled(
                                            true
                                        );


                                        showInfo(
                                            "VAPT Sanitizer — AI Handoff",
                                            (
                                                "AI-ready prompt copied to clipboard.\n\n"
                                                + "No data was sent automatically.\n"
                                                + "Paste it manually into the AI conversation "
                                                + "you want to use in your browser."
                                            )
                                        );
                                    }
                                );


                            } catch (
                                Exception exc
                            ) {

                                api.logging().logToError(
                                    "AI handoff failed: "
                                    + safeMessage(
                                        exc
                                    )
                                );


                                SwingUtilities.invokeLater(
                                    () -> {

                                        copyAiPromptButton.setText(
                                            "Copy AI Prompt"
                                        );

                                        copyAiPromptButton.setEnabled(
                                            !"BLOCKED".equals(
                                                result.securityGate
                                            )
                                        );


                                        showError(
                                            "VAPT Sanitizer",
                                            "AI handoff failed:\n\n"
                                            + safeMessage(
                                                exc
                                            )
                                        );
                                    }
                                );
                            }
                        },
                        "vapt-sanitizer-ai-handoff-worker"
                    );


                handoffWorker.setDaemon(
                    true
                );

                handoffWorker.start();
            }
        );


        JPanel buttons =
            new JPanel(
                new FlowLayout(
                    FlowLayout.RIGHT
                )
            );


        buttons.add(
            cancelButton
        );

        buttons.add(
            copyButton
        );

        buttons.add(
            copyAiPromptButton
        );


        root.add(
            buttons,
            BorderLayout.SOUTH
        );


        api.userInterface()
            .applyThemeToComponent(
                root
            );


        dialog.setContentPane(
            root
        );

        dialog.setSize(
            900,
            700
        );

        dialog.setLocationRelativeTo(
            null
        );

        dialog.setVisible(
            true
        );
    }


    private LLMTask selectedLlmTask() {

        if (
            taskCombo == null
        ) {

            return LLMTask.ANALYZE_SECURITY;
        }


        Object selected =
            taskCombo.getSelectedItem();


        if (
            selected
                instanceof LLMTask
        ) {

            return (LLMTask)
                selected;
        }


        return LLMTask.ANALYZE_SECURITY;
    }


    private String selectedLlmQuestion() {

        if (
            llmQuestionArea == null
        ) {

            return null;
        }


        String value =
            llmQuestionArea.getText();


        if (
            value == null
            || value.isBlank()
        ) {

            return null;
        }


        return value.trim();
    }


    private String sourceLabelForType(
        String type
    ) {

        if (
            "request".equalsIgnoreCase(
                type
            )
        ) {

            return "Burp HTTP Request";
        }


        if (
            "response".equalsIgnoreCase(
                type
            )
        ) {

            return "Burp HTTP Response";
        }


        if (
            "selection".equalsIgnoreCase(
                type
            )
        ) {

            return "Burp Selection";
        }


        return "Burp Suite";
    }


    private String runAiHandoff(
        String sanitized,
        LLMTask task,
        String gateState,
        boolean reviewApproved,
        PolicyMode policyMode,
        String question,
        String source
    ) throws Exception {

        String home =
            sanitizerHome();

        String python =
            sanitizerPython(
                home
            );


        List<String> command =
            new ArrayList<>();


        command.add(
            python
        );

        command.add(
            "-m"
        );

        command.add(
            "vapt_sanitize.llm.handoff"
        );


        command.add(
            "--task"
        );

        command.add(
            task.name()
        );


        command.add(
            "--gate"
        );

        command.add(
            gateState
        );


        if (
            reviewApproved
        ) {

            command.add(
                "--review-approved"
            );
        }


        if (
            policyMode.relativePath
                != null
        ) {

            File policyFile =
                new File(
                    home,
                    policyMode.relativePath
                );


            if (
                !policyFile.isFile()
            ) {

                throw new IllegalStateException(
                    "Policy file not found: "
                    + policyFile.getAbsolutePath()
                );
            }


            command.add(
                "--policy"
            );

            command.add(
                policyFile.getAbsolutePath()
            );
        }


        command.add(
            "--policy-name"
        );

        command.add(
            policyMode.displayName
        );


        if (
            question != null
            && !question.isBlank()
        ) {

            command.add(
                "--question-b64"
            );

            command.add(
                encodeBase64(
                    question
                )
            );
        }


        command.add(
            "--source-b64"
        );

        command.add(
            encodeBase64(
                source
            )
        );


        ProcessBuilder builder =
            new ProcessBuilder(
                command
            );


        builder.directory(
            new File(
                home
            )
        );


        Process process =
            builder.start();


        /*
         * SECURITY BOUNDARY:
         *
         * Only already-sanitized Burp content is passed
         * into the AI handoff builder.
         *
         * The handoff builder performs no network call.
         */
        process.getOutputStream()
            .write(
                sanitized.getBytes(
                    StandardCharsets.UTF_8
                )
            );

        process.getOutputStream()
            .close();


        boolean finished =
            process.waitFor(
                15,
                TimeUnit.SECONDS
            );


        if (
            !finished
        ) {

            process.destroyForcibly();

            throw new IllegalStateException(
                "AI handoff builder timeout."
            );
        }


        byte[] stdout =
            process.getInputStream()
                .readAllBytes();

        byte[] stderr =
            process.getErrorStream()
                .readAllBytes();


        if (
            process.exitValue()
                != 0
        ) {

            String error =
                new String(
                    stderr,
                    StandardCharsets.UTF_8
                ).trim();


            throw new IllegalStateException(
                error.isEmpty()
                    ? "AI handoff builder failed."
                    : error
            );
        }


        String protocol =
            new String(
                stdout,
                StandardCharsets.UTF_8
            );


        return parseAiHandoffProtocol(
            protocol
        );
    }


    private String parseAiHandoffProtocol(
        String protocol
    ) {

        String[] lines =
            protocol.split(
                "\\R"
            );


        if (
            lines.length == 0
            || !AI_HANDOFF_HEADER.equals(
                lines[0].trim()
            )
        ) {

            throw new IllegalStateException(
                "Invalid AI handoff protocol."
            );
        }


        String prompt =
            null;

        boolean ended =
            false;


        for (
            int i = 1;
            i < lines.length;
            i++
        ) {

            String line =
                lines[i];


            if (
                line.startsWith(
                    "PROMPT_B64:"
                )
            ) {

                prompt =
                    decodeBase64(
                        line.substring(
                            "PROMPT_B64:"
                                .length()
                        )
                    );


            } else if (
                "END".equals(
                    line
                )
            ) {

                ended =
                    true;

                break;
            }
        }


        if (
            !ended
            || prompt == null
            || prompt.isBlank()
        ) {

            throw new IllegalStateException(
                "Incomplete AI handoff response."
            );
        }


        return prompt;
    }


    private String encodeBase64(
        String value
    ) {

        return Base64.getEncoder()
            .encodeToString(
                value.getBytes(
                    StandardCharsets.UTF_8
                )
            );
    }


    private void writeAndVerifyClipboard(
        String sanitized
    ) throws Exception {

        if (
            sanitized == null
            || sanitized.isEmpty()
        ) {

            throw new IllegalArgumentException(
                "Refusing to write empty clipboard content."
            );
        }


        Clipboard clipboard =
            Toolkit
                .getDefaultToolkit()
                .getSystemClipboard();


        clipboard.setContents(
            new StringSelection(
                sanitized
            ),
            null
        );


        String clipboardText =
            (String) clipboard.getData(
                DataFlavor.stringFlavor
            );


        if (
            !sanitized.equals(
                clipboardText
            )
        ) {

            throw new IllegalStateException(
                "Clipboard verification failed."
            );
        }
    }


    private static String safeMessage(
        Exception exc
    ) {

        String message =
            exc.getMessage();


        if (
            message == null
            || message.isBlank()
        ) {

            return exc.getClass()
                .getSimpleName();
        }


        return message;
    }


    private void showInfo(
        String title,
        String message
    ) {

        SwingUtilities.invokeLater(
            () ->
                JOptionPane.showMessageDialog(
                    null,
                    message,
                    title,
                    JOptionPane.INFORMATION_MESSAGE
                )
        );
    }


    private void showError(
        String title,
        String message
    ) {

        SwingUtilities.invokeLater(
            () ->
                JOptionPane.showMessageDialog(
                    null,
                    message,
                    title,
                    JOptionPane.ERROR_MESSAGE
                )
        );
    }


    private enum LLMTask {

        ANALYZE_SECURITY(
            "Analyze security"
        ),

        EXPLAIN_RESPONSE(
            "Explain response"
        ),

        FIND_ATTACK_SURFACE(
            "Find attack surface"
        ),

        SUGGEST_NEXT_TESTS(
            "Suggest next tests"
        ),

        CUSTOM(
            "Custom question"
        );


        private final String displayName;


        LLMTask(
            String displayName
        ) {

            this.displayName =
                displayName;
        }


        @Override
        public String toString() {

            return displayName;
        }
    }


    private enum PolicyMode {

        DEFAULT(
            "Default",
            null
        ),

        AGGRESSIVE_PII(
            "Aggressive PII",
            "policies/aggressive_pii.yml"
        ),

        STRICT_LLM(
            "Strict LLM",
            "policies/strict_llm.yml"
        );


        private final String displayName;

        private final String relativePath;


        PolicyMode(
            String displayName,
            String relativePath
        ) {

            this.displayName =
                displayName;

            this.relativePath =
                relativePath;
        }


        @Override
        public String toString() {

            return displayName;
        }
    }


    private static class RuntimeProbe {

        private final String
            preservedFinding;

        private final String
            noFindings;


        private RuntimeProbe(
            String preservedFinding,
            String noFindings
        ) {

            this.preservedFinding =
                preservedFinding;

            this.noFindings =
                noFindings;
        }
    }


    private static class PreviewResult {

        private final String sanitized;

        private final List<FindingSummary>
            findings;

        private final String securityGate;

        private final String securityGateReason;


        private PreviewResult(
            String sanitized,
            List<FindingSummary> findings,
            String securityGate,
            String securityGateReason
        ) {

            this.sanitized =
                sanitized;

            this.findings =
                findings;

            this.securityGate =
                securityGate;

            this.securityGateReason =
                securityGateReason;
        }
    }


    private static class FindingSummary {

        private final String category;

        private final String action;

        private final String reason;


        private FindingSummary(
            String category,
            String action,
            String reason
        ) {

            this.category =
                category;

            this.action =
                action;

            this.reason =
                reason;
        }
    }
}

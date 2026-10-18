#pragma once

#include <QMainWindow>
#include <QString>
#include <QUrl>

class QDockWidget;
class QLabel;
class QLineEdit;
class QListWidget;
class QSpinBox;
class QTabWidget;
class QTextEdit;
class QPushButton;
class QWebEnginePage;
class QWebEngineProfile;
class QWebEngineView;
class VX6Backend;

class BrowserWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit BrowserWindow(const QString &vx6Binary, const QString &configPath, QWidget *parent = nullptr);

private slots:
    void openAddress();
    void openHome();
    void newTab();
    void closeTab(int index);
    void currentTabChanged(int index);
    void toggleLogs();
    void copyCurrentIpv6();
    void refreshControlPanel();
    void renameNodeFromPanel();
    void lookupServiceFromPanel();
    void lookupNodeFromPanel();
    void lookupHiddenFromPanel();
    void hostServiceFromPanel();
    void stopHostedServiceFromPanel();
    void initializeNodeFromPanel();
    void connectServiceFromPanel();
    void chooseFileFromPanel();
    void sendFileFromPanel();
    void toggleReceiveFromPanel();
    void showFileTransferPage();
    void reloadNode();
    void startNode();
    void stopNode();
    void refreshStatus();
    void bookmarkCurrent();

private:
    void buildUi();
    void buildToolbar();
    void buildControlDock();
    void buildDock();
    void registerBrowserCallbacks();
    void maybeShowPermissionPrompt();
    void navigateTo(const QString &text, bool newTab = false);
    QString normalizeTarget(const QString &raw) const;
    QWebEngineView *currentView() const;
    QWebEngineView *createTab(const QUrl &initialUrl);
    void appendLog(const QString &line);

    VX6Backend *m_backend;
    QWebEngineProfile *m_profile;
    QTabWidget *m_tabs;
    QLineEdit *m_address;
    QDockWidget *m_controlDock;
    QLineEdit *m_ipv6Field;
    QLineEdit *m_nodeNameField;
    QLineEdit *m_nodeIdField;
    QLineEdit *m_initNodeNameField;
    QLineEdit *m_connectServiceField;
    QLineEdit *m_renameField;
    QLineEdit *m_lookupField;
    QLineEdit *m_hostNameField;
    QSpinBox *m_hostPortField;
    QLineEdit *m_sendFileField;
    QLineEdit *m_sendTargetField;
    QPushButton *m_toggleReceiveBtn;
    QTextEdit *m_lookupResult;
    QTextEdit *m_logView;
    QDockWidget *m_logDock;
    QListWidget *m_shortcuts;
};

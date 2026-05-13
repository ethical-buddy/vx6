#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

class VX6Backend : public QObject
{
    Q_OBJECT

public:
    explicit VX6Backend(QString vx6Binary, QString configPath, QObject *parent = nullptr);

    QString vx6Binary() const;
    QString configPath() const;
    void setVx6Binary(const QString &path);
    void setConfigPath(const QString &path);

    bool needsPermissionPrompt() const;
    QString permissionPromptHtml() const;
    QString homePageHtml() const;
    QString statusPageHtml() const;
    QString dhtPageHtml() const;
    QString registryPageHtml() const;
    QString servicesPageHtml() const;
    QString peersPageHtml() const;
    QString identityPageHtml() const;
    QString lookupPageHtml(const QString &title, const QStringList &args, const QString &subtitle) const;
    QString currentNodeName() const;
    QString currentNodeID() const;
    QString currentAdvertiseAddr() const;
    QString sendFile(const QString &filePath, const QString &target, bool proxy = false);
    QString receiveStatus() const;
    bool receiveEnabled() const;
    QString toggleReceive(bool enable);
    QString filesPageHtml() const;
    QString transfersPageHtml() const;
    QString sentTransfersHtml() const;

    bool nodeRunning() const;
    QString currentDownloadPath() const;
    QString downloadedFilesHtml(const QString &downloadDir) const;
    QString startNode();
    QString stopNode();
    QString renameNode(const QString &name);
    QString initializeNode(const QString &name);
    QString connectService(const QString &target);
    QString hostService(const QString &serviceName, int port);
    QString stopHostedService(const QString &serviceName);
    QString lookupRaw(const QStringList &args, const QString &label) const;

    QString runVX6(const QStringList &args, bool *ok = nullptr) const;
    QString resolveConfigPath() const;
    QString resolveBinaryPath() const;
    
    bool vx6BinaryExists() const;
    QString ensureVx6Binary();

signals:
    void logLine(const QString &line) const;

private:
    void appendProcessOutput();
    void updateNodeState();
    QString statusValue(const QString &key) const;

    QString makePageShell(const QString &title, const QString &headline, const QString &body, const QString &accent) const;
    QString dashboardCard(const QString &href, const QString &title, const QString &description, const QString &accent) const;
    QString commandBlock(const QString &output) const;
    QString browserHintBlock() const;
    QString osNoticeBlock() const;
    
    bool waitForProcessFinished(QProcess &proc, int msecs) const;

    QString m_vx6Binary;
    QString m_configPath;
    mutable QProcess m_nodeProcess;
};

#include "vx6backend.h"

#include <QApplication>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QStringList>
#include <QTextStream>
#include <QDateTime>

#include <chrono>
#include <thread>

VX6Backend::VX6Backend(QString vx6Binary, QString configPath, QObject *parent)
    : QObject(parent), m_vx6Binary(std::move(vx6Binary)), m_configPath(std::move(configPath))
{
    m_nodeProcess.setProcessChannelMode(QProcess::MergedChannels);
    connect(&m_nodeProcess, &QProcess::readyReadStandardOutput, this, &VX6Backend::appendProcessOutput);
    connect(&m_nodeProcess, &QProcess::readyReadStandardError, this, &VX6Backend::appendProcessOutput);
    connect(&m_nodeProcess, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
        emit logLine(QStringLiteral("vx6 node stopped"));
        updateNodeState();
    });
}

QString VX6Backend::vx6Binary() const
{
    return m_vx6Binary;
}

QString VX6Backend::configPath() const
{
    return m_configPath;
}

void VX6Backend::setVx6Binary(const QString &path)
{
    m_vx6Binary = path;
}

void VX6Backend::setConfigPath(const QString &path)
{
    m_configPath = path;
}

bool VX6Backend::needsPermissionPrompt() const
{
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    return true;
#else
    return false;
#endif
}

QString VX6Backend::resolveBinaryPath() const
{
    if (!m_vx6Binary.trimmed().isEmpty()) {
        return m_vx6Binary.trimmed();
    }

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
#if defined(Q_OS_WIN)
        QDir(appDir).filePath("vx6.exe"),
        QDir(appDir).filePath("vx6"),
#else
        QDir(appDir).filePath("vx6"),
#endif
    };

    for (const QString &candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return candidate;
        }
    }
    const QString fromPath = QStandardPaths::findExecutable(QStringLiteral("vx6"));
    if (!fromPath.isEmpty()) {
        return fromPath;
    }
    return QStringLiteral("vx6");
}

QString VX6Backend::resolveConfigPath() const
{
    if (!m_configPath.trimmed().isEmpty()) {
        return QDir::cleanPath(m_configPath.trimmed());
    }

    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (!base.isEmpty()) {
        return QDir(base).filePath("config.json");
    }
    return QStringLiteral("config.json");
}

bool VX6Backend::vx6BinaryExists() const
{
    const QString binPath = resolveBinaryPath();
    return QFileInfo::exists(binPath) && QFileInfo(binPath).isExecutable();
}

bool VX6Backend::waitForProcessFinished(QProcess &proc, int msecs) const
{
    const auto start = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::milliseconds(msecs);
    
    while (proc.state() == QProcess::Running) {
        const auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            return false;  // Timeout
        }
        
        // Process UI events to keep interface responsive
        QApplication::processEvents(QEventLoop::AllEvents, 100);
        
        // Small sleep to avoid busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    return true;  // Process finished normally
}

QString VX6Backend::ensureVx6Binary()
{
    if (vx6BinaryExists()) {
        emit logLine(QStringLiteral("vx6 binary already available"));
        return QStringLiteral("vx6 binary already available");
    }

    emit logLine(QStringLiteral("vx6 binary not found, building from source..."));

    const QString appDir = QCoreApplication::applicationDirPath();
    QDir dir(appDir);
    dir.cdUp();  // qt/build -> qt
    dir.cdUp();  // qt -> browser
    dir.cdUp();  // browser -> project root
    const QString projectRoot = dir.path();
    
    const QString buildCmd = QStringLiteral("go build -o %1 ./cmd/vx6")
        .arg(QDir(appDir).filePath("vx6"));

    QProcess buildProc;
    buildProc.setWorkingDirectory(projectRoot);
    buildProc.setProgram(QStringLiteral("sh"));
    buildProc.setArguments({QStringLiteral("-c"), buildCmd});

    emit logLine(QStringLiteral("building vx6 in: %1").arg(projectRoot));
    buildProc.start();

    if (!buildProc.waitForStarted(5000)) {
        const QString msg = QStringLiteral("failed to start build process");
        emit logLine(msg);
        return msg;
    }

    if (!buildProc.waitForFinished(300000)) {  // 5 minute timeout
        buildProc.kill();
        buildProc.waitForFinished(2000);
        const QString msg = QStringLiteral("vx6 build timed out");
        emit logLine(msg);
        return msg;
    }

    const QString buildOutput = QString::fromUtf8(buildProc.readAllStandardOutput());
    const QString buildError = QString::fromUtf8(buildProc.readAllStandardError());
    const bool buildSuccess = buildProc.exitStatus() == QProcess::NormalExit && buildProc.exitCode() == 0;

    if (!buildError.trimmed().isEmpty()) {
        emit logLine(buildError);
    }
    if (!buildOutput.trimmed().isEmpty()) {
        emit logLine(buildOutput);
    }

    if (buildSuccess && vx6BinaryExists()) {
        emit logLine(QStringLiteral("vx6 binary built successfully"));
        return QStringLiteral("vx6 binary built successfully");
    }

    const QString msg = QStringLiteral("failed to build vx6 binary (exit code %1)").arg(buildProc.exitCode());
    emit logLine(msg);
    return msg;
}

QString VX6Backend::runVX6(const QStringList &args, bool *ok) const
{
    QProcess proc;
    proc.setProgram(resolveBinaryPath());
    proc.setArguments(args);

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QString cfg = resolveConfigPath();
    if (!cfg.isEmpty()) {
        env.insert(QStringLiteral("VX6_CONFIG_PATH"), cfg);
    }
    proc.setProcessEnvironment(env);
    proc.start();
    if (!proc.waitForStarted(5000)) {
        if (ok) {
            *ok = false;
        }
        const QString msg = QStringLiteral("failed to start vx6 binary: %1").arg(resolveBinaryPath());
        emit logLine(msg);
        return msg;
    }
    
    // Use responsive wait to keep UI responsive during long operations
    if (!waitForProcessFinished(proc, 120000)) {
        proc.kill();
        proc.waitForFinished(2000);
        if (ok) {
            *ok = false;
        }
        const QString msg = QStringLiteral("vx6 command timed out: %1").arg(args.join(' '));
        emit logLine(msg);
        return msg;
    }

    const QString out = QString::fromUtf8(proc.readAllStandardOutput());
    const QString err = QString::fromUtf8(proc.readAllStandardError());
    const bool success = proc.exitStatus() == QProcess::NormalExit && proc.exitCode() == 0;
    if (ok) {
        *ok = success;
    }

    QString combined = out;
    if (!err.trimmed().isEmpty()) {
        if (!combined.endsWith('\n') && !combined.isEmpty()) {
            combined += '\n';
        }
        combined += err;
    }
    const QString line = QStringLiteral("[%1] %2").arg(success ? "ok" : "fail", args.join(' '));
    emit logLine(line);
    if (!success && combined.trimmed().isEmpty()) {
        combined = QStringLiteral("vx6 command failed with exit code %1").arg(proc.exitCode());
    }
    return combined;
}

QString VX6Backend::browserHintBlock() const
{
    return QStringLiteral(
        "<div class=\"hint\"><strong>Browser mode:</strong> "
        "VX6 pages are opened through <code>vx6://</code>. "
        "Standard <code>http://</code> and <code>https://</code> pages stay available.</div>");
}

QString VX6Backend::osNoticeBlock() const
{
#if defined(Q_OS_WIN)
    return QStringLiteral(
        "<div class=\"notice warn\"><strong>Windows start-up:</strong> "
        "allow firewall/admin setup during first launch so service discovery works later without prompts.</div>");
#elif defined(Q_OS_MACOS)
    return QStringLiteral(
        "<div class=\"notice warn\"><strong>macOS start-up:</strong> "
        "grant network and firewall permissions during first launch so VX6 can publish and connect cleanly.</div>");
#else
    return QStringLiteral(
        "<div class=\"notice ok\"><strong>Linux/BSD start-up:</strong> "
        "VX6 runs with the same backend; platform-specific firewall prompts are not forced here.</div>");
#endif
}

QString VX6Backend::dashboardCard(const QString &href, const QString &title, const QString &description, const QString &accent) const
{
    return QStringLiteral(
        "<a class=\"card\" href=\"%1\" style=\"--accent:%4\">"
        "<span class=\"card-title\">%2</span>"
        "<span class=\"card-desc\">%3</span>"
        "</a>")
        .arg(href, title, description, accent);
}

QString VX6Backend::commandBlock(const QString &output) const
{
    return QStringLiteral("<pre class=\"output\">%1</pre>").arg(output.toHtmlEscaped());
}

QString VX6Backend::makePageShell(const QString &title, const QString &headline, const QString &body, const QString &accent) const
{
    QString page = QStringLiteral(R"HTML(
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
:root {
  color-scheme: dark;
  --text: #eef4ff;
  --muted: #a8b3ca;
  --accent: {{ACCENT}};
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, Segoe UI, Arial, sans-serif;
  background:
    radial-gradient(circle at top left, rgba(27, 111, 255, 0.20), transparent 28%),
    radial-gradient(circle at top right, rgba(6, 214, 160, 0.18), transparent 26%),
    linear-gradient(180deg, #07111d 0%, #0c1426 100%);
  color: var(--text);
}
.wrap { padding: 28px; max-width: 1240px; margin: 0 auto; }
.banner, .panel, .notice, .hint, .card, .output {
  border-radius: 20px;
  border: 1px solid rgba(255,255,255,0.08);
  background: rgba(16, 27, 49, 0.84);
  box-shadow: 0 12px 40px rgba(0,0,0,0.22);
}
.banner { padding: 24px; background: linear-gradient(145deg, rgba(16,27,49,.95), rgba(19,32,58,.86)); }
.panel { padding: 20px; margin-top: 18px; }
.title { margin: 0 0 10px; font-size: 42px; letter-spacing: 0.02em; }
.subtitle { margin: 0 0 18px; color: var(--muted); line-height: 1.6; }
.notice, .hint { padding: 16px 18px; margin: 0 0 14px; }
.notice.ok { border-color: rgba(6, 214, 160, 0.30); }
.notice.warn { border-color: rgba(255, 194, 102, 0.34); }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 14px;
}
.card {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  min-height: 120px;
  padding: 18px;
  color: var(--text);
  text-decoration: none;
  border-left: 6px solid var(--accent);
  background: linear-gradient(180deg, rgba(20,31,54,.96), rgba(14,22,40,.96));
}
.card:hover { transform: translateY(-2px); }
.card-title { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
.card-desc { color: var(--muted); line-height: 1.45; }
.section { margin-top: 22px; }
.section h2 { margin: 0 0 12px; font-size: 22px; }
.output {
  padding: 18px;
  overflow: auto;
  white-space: pre-wrap;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 13px;
  line-height: 1.55;
}
.footer { margin-top: 24px; color: var(--muted); font-size: 13px; }
code { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 6px; }
a { color: #79b8ff; }
</style>
</head>
<body>
<div class="wrap">
  <div class="banner">
    <h1 class="title">{{TITLE}}</h1>
    <p class="subtitle">{{HEADLINE}}</p>
    {{HINT}}
    {{NOTICE}}
  </div>
  {{BODY}}
  <div class="footer">
    Shell accent: <span style="color:{{ACCENT}};">{{ACCENT}}</span> • backed by the current VX6 binary • no profile switching
  </div>
</div>
</body>
</html>
)HTML");

    page.replace("{{TITLE}}", title.toHtmlEscaped());
    page.replace("{{HEADLINE}}", headline.toHtmlEscaped());
    page.replace("{{ACCENT}}", accent.toHtmlEscaped());
    page.replace("{{HINT}}", browserHintBlock());
    page.replace("{{NOTICE}}", osNoticeBlock());
    page.replace("{{BODY}}", body);
    return page;
}

QString VX6Backend::homePageHtml() const
{
    bool ok = false;
    const QString status = runVX6(QStringList{"status"}, &ok);
    const QString dht = runVX6(QStringList{"debug", "dht-status"}, &ok);
    const QString peers = runVX6(QStringList{"peer"}, &ok);

    QString cards;
    cards += dashboardCard("vx6://status", "Status", "Show live runtime status and current node health.", "#6ea8ff");
    cards += dashboardCard("vx6://dht", "DHT", "Open lookup, replication, and resolver health.", "#23c18f");
    cards += dashboardCard("vx6://registry", "Registry", "Inspect the discovery registry snapshot.", "#ffd166");
    cards += dashboardCard("vx6://services", "Services", "View local configured services.", "#f78c6b");
    cards += dashboardCard("vx6://transfers","Transfers","View grouped received files and transfer history.","#4cd137");


    QString body;
    body += QStringLiteral(
        "<div class=\"panel\" style=\"margin-top:18px;\">"
        "<div class=\"notice ok\"><strong>Control drawer:</strong> Use the left sliding panel for copy, rename, lookup, and service hosting. "
        "The home screen stays focused on overview.</div>"
        "</div>");
    body += QStringLiteral("<div class=\"grid\">%1</div>").arg(cards);
    body += QStringLiteral("<div class=\"section\"><h2>Live Status Snapshot</h2>%1</div>").arg(commandBlock(status));
    body += QStringLiteral("<div class=\"section\"><h2>DHT Snapshot</h2>%1</div>").arg(commandBlock(dht));
    body += QStringLiteral("<div class=\"section\"><h2>Peer Snapshot</h2>%1</div>").arg(commandBlock(peers));
    body += QStringLiteral(
        "<div class=\"section\"><h2>Shortcuts</h2>"
        "<div class=\"hint\">Use <code>vx6://status</code>, <code>vx6://dht</code>, <code>vx6://services</code>, "
        "<code>vx6://peers</code>, <code>vx6://transfers</code> and <code>vx6://identity</code> as your overview pages. Operational actions live in the left drawer.</div>"
        "</div>");

    return makePageShell("VX6 Home", "One system. One key. One VX6 runtime.", body, "#6ea8ff");
}

QString VX6Backend::statusPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"status"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">Live runtime status from the current VX6 binary.</div>"
        "<div class=\"section\"><h2>Status Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 Status", "Live runtime status", body, "#6ea8ff");
}

QString VX6Backend::dhtPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"debug", "dht-status"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">Lookup health, ASN diversity, replicas, and refresh state.</div>"
        "<div class=\"section\"><h2>DHT Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 DHT", "DHT health and lookup state", body, "#23c18f");
}

QString VX6Backend::registryPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"debug", "registry"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">Discovery registry snapshot from the current node.</div>"
        "<div class=\"section\"><h2>Registry Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 Registry", "Discovery registry", body, "#ffd166");
}

QString VX6Backend::servicesPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"service"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">Local configured services. Public, private, and hidden services are all surfaced here.</div>"
        "<div class=\"section\"><h2>Services Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 Services", "Local services", body, "#f78c6b");
}

QString VX6Backend::peersPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"peer"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">Known peers are the seed list used at startup and for later sync.</div>"
        "<div class=\"section\"><h2>Peer Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 Peers", "Peer directory", body, "#8f7cff");
}

QString VX6Backend::identityPageHtml() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"identity"}, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">One system, one key. The display name can change; the key stays fixed.</div>"
        "<div class=\"section\"><h2>Identity Output</h2>%1</div>")
        .arg(commandBlock(output));
    return makePageShell("VX6 Identity", "Identity and key details", body, "#4dd0e1");
}

QString VX6Backend::lookupPageHtml(const QString &title, const QStringList &args, const QString &subtitle) const
{
    bool ok = false;
    const QString output = runVX6(args, &ok);
    const QString body = QStringLiteral(
        "<div class=\"hint\">%1</div>"
        "<div class=\"section\"><h2>%2 Output</h2>%3</div>")
        .arg(subtitle.toHtmlEscaped(), title.toHtmlEscaped(), commandBlock(output));
    return makePageShell(title, subtitle, body, "#c792ea");
}

QString VX6Backend::currentNodeName() const
{
    return statusValue(QStringLiteral("node_name"));
}

QString VX6Backend::currentNodeID() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"identity"}, &ok);
    for (const QString &line : output.split('\n', Qt::SkipEmptyParts)) {
        const int tab = line.indexOf('\t');
        if (tab <= 0) {
            continue;
        }
        const QString key = line.left(tab).trimmed();
        const QString value = line.mid(tab + 1).trimmed();
        if (key == "node_id") {
            return value;
        }
    }
    return QString();
}

QString VX6Backend::currentAdvertiseAddr() const
{
    return statusValue(QStringLiteral("advertise_addr"));
}

QString VX6Backend::statusValue(const QString &key) const
{
    bool ok = false;
    const QString output = runVX6(QStringList{"status"}, &ok);
    for (const QString &line : output.split('\n', Qt::SkipEmptyParts)) {
        const int tab = line.indexOf('\t');
        if (tab <= 0) {
            continue;
        }
        const QString foundKey = line.left(tab).trimmed();
        const QString value = line.mid(tab + 1).trimmed();
        if (foundKey == key) {
            return value;
        }
    }
    return QString();
}

bool VX6Backend::nodeRunning() const
{
    return m_nodeProcess.state() != QProcess::NotRunning;
}

QString VX6Backend::startNode()
{
    if (nodeRunning()) {
        return QStringLiteral("vx6 node already running");
    }

    m_nodeProcess.setProgram(resolveBinaryPath());
    m_nodeProcess.setArguments({"node"});
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QString cfg = resolveConfigPath();
    if (!cfg.isEmpty()) {
        env.insert(QStringLiteral("VX6_CONFIG_PATH"), cfg);
    }
    m_nodeProcess.setProcessEnvironment(env);
    m_nodeProcess.start();
    if (!m_nodeProcess.waitForStarted(5000)) {
        return QStringLiteral("failed to start vx6 node: %1").arg(resolveBinaryPath());
    }

    updateNodeState();
    emit logLine(QStringLiteral("vx6 node started"));
    return QStringLiteral("vx6 node started");
}

QString VX6Backend::stopNode()
{
    if (!nodeRunning()) {
        return QStringLiteral("vx6 node is not running");
    }

    m_nodeProcess.terminate();
    if (!m_nodeProcess.waitForFinished(3000)) {
        m_nodeProcess.kill();
        m_nodeProcess.waitForFinished(2000);
    }
    updateNodeState();
    return QStringLiteral("vx6 node stopped");
}

QString VX6Backend::renameNode(const QString &name)
{
    const QString trimmed = name.trimmed();
    if (trimmed.isEmpty()) {
        return QStringLiteral("node rename failed: empty name");
    }
    bool ok = false;
    const QString output = runVX6(QStringList{"identity", "rename", "--name", trimmed, "--wait", "1m"}, &ok);
    if (ok) {
        const QString reloadOut = runVX6(QStringList{"reload"}, &ok);
        return output + QStringLiteral("\n") + reloadOut;
    }
    return output;
}

QString VX6Backend::initializeNode(const QString &name)
{
    const QString trimmed = name.trimmed();
    if (trimmed.isEmpty()) {
        return QStringLiteral("node init failed: empty name");
    }
    bool ok = false;
    
    // Step 1: Stop the running node
    if (nodeRunning()) {
        emit logLine(QStringLiteral("stopping running node..."));
        m_nodeProcess.terminate();
        if (!m_nodeProcess.waitForFinished(3000)) {
            m_nodeProcess.kill();
            m_nodeProcess.waitForFinished(2000);
        }
        updateNodeState();
        emit logLine(QStringLiteral("node stopped"));
    }
    
    // Step 2: Run init
    emit logLine(QStringLiteral("initializing new node with name: %1").arg(trimmed));
    emit logLine(QStringLiteral("generating keys... this may take a moment"));
    
    const QString initOut = runVX6(
        QStringList{"init", "--name", trimmed, "--listen", "[::]:4242"},
        &ok);
    
    if (!ok) {
        emit logLine(QStringLiteral("initialization failed"));
        emit logLine(initOut);
        return initOut;
    }
    
    // Step 3: Start the new node
    emit logLine(QStringLiteral("node initialized, starting new node..."));
    const QString startResult = startNode();
    emit logLine(startResult);
    
    return QStringLiteral("node reinitialized successfully");
}

QString VX6Backend::connectService(const QString &target)
{
    const QString trimmed = target.trimmed();
    if (trimmed.isEmpty()) {
        return QStringLiteral("connect failed: empty target");
    }
    bool ok = false;
    emit logLine(QStringLiteral("connecting to: %1").arg(trimmed));
    const QString output = runVX6(QStringList{"connect", "--service", trimmed, "--listen", "127.0.0.1:9999"}, &ok);
    if (ok) {
        return QStringLiteral("Connected to %1 on 127.0.0.1:9999\n%2").arg(trimmed, output);
    }
    return output;
}

QString VX6Backend::hostService(const QString &serviceName, int port)
{
    const QString trimmed = serviceName.trimmed();
    if (trimmed.isEmpty() || port <= 0 || port > 65535) {
        return QStringLiteral("service host failed: invalid name or port");
    }
    bool ok = false;
    const QString target = QStringLiteral("127.0.0.1:%1").arg(port);
    const QString output = runVX6(QStringList{"service", "add", "--name", trimmed, "--target", target}, &ok);
    if (ok) {
        const QString reloadOut = runVX6(QStringList{"reload"}, &ok);
        return output + QStringLiteral("\n") + reloadOut;
    }
    return output;
}

QString VX6Backend::sendFile(const QString &filePath, const QString &target, bool proxy)
{
    const QString trimmedFile = filePath.trimmed();
    const QString trimmedTarget = target.trimmed();
    if (trimmedFile.isEmpty()) {
        return QStringLiteral("send file failed: empty file path");
    }
    if (trimmedTarget.isEmpty()) {
        return QStringLiteral("send file failed: empty target");
    }
    if (!QFileInfo(trimmedFile).exists()) {
        return QStringLiteral("send file failed: file does not exist");
    }

    QStringList args = {QStringLiteral("send"), QStringLiteral("--file"), trimmedFile};
    if (trimmedTarget.contains(QLatin1Char(':'))) {
        args << QStringLiteral("--addr") << trimmedTarget;
    } else {
        args << QStringLiteral("--to") << trimmedTarget;
    }
    if (proxy) {
        args << QStringLiteral("--proxy");
    }

    bool ok = false;
    const QString result = runVX6(args, &ok);
    if (ok) {
        QFile historyFile(QDir::homePath() + "/.vx6-transfer-history.log");

        if (historyFile.open(QIODevice::Append | QIODevice::Text))
        {
            QTextStream out(&historyFile);

            out << QDateTime::currentDateTime().toString(Qt::ISODate)
                << "|SEND|SUCCESS|"
                << QFileInfo(trimmedFile).fileName()
                << "|"
                << trimmedTarget
                << "\n";
        }
        return QStringLiteral("file send complete:\n%1").arg(result.trimmed());
    }
    QFile historyFile(QDir::homePath() + "/.vx6-transfer-history.log");

        if (historyFile.open(QIODevice::Append | QIODevice::Text))
        {
            QTextStream out(&historyFile);

            out << QDateTime::currentDateTime().toString(Qt::ISODate)
                << "|SEND|FAILED|"
                << QFileInfo(trimmedFile).fileName()
                << "|"
                << trimmedTarget
                << "\n";
        }
    return QStringLiteral("file send failed:\n%1").arg(result.trimmed());
}

QString VX6Backend::receiveStatus() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{QStringLiteral("receive"), QStringLiteral("status")}, &ok);
    if (ok) {
        return QStringLiteral("receive status:\n%1").arg(output.trimmed());
    }
    return QStringLiteral("receive status failed:\n%1").arg(output.trimmed());
}

bool VX6Backend::receiveEnabled() const
{
    bool ok = false;
    const QString output = runVX6(QStringList{QStringLiteral("receive"), QStringLiteral("status")}, &ok);
    if (!ok) {
        return false;
    }
    for (const QString &line : output.split('\n', Qt::SkipEmptyParts)) {
        if (line.startsWith(QStringLiteral("file_receive_mode\t"))) {
            const QString mode = line.section('\t', 1, 1).trimmed();
            return mode == QStringLiteral("OPEN") || mode == QStringLiteral("TRUSTED");
        }
    }
    return false;
}

QString VX6Backend::toggleReceive(bool enable)
{
    QStringList args;
    if (enable) {
        args = {QStringLiteral("receive"), QStringLiteral("allow"), QStringLiteral("--all")};
    } else {
        args = {QStringLiteral("receive"), QStringLiteral("disable")};
    }
    bool ok = false;
    const QString output = runVX6(args, &ok);
    if (ok) {
        return QStringLiteral("receive %1 successfully:\n%2").arg(enable ? QStringLiteral("enabled") : QStringLiteral("disabled"), output.trimmed());
    }
    return QStringLiteral("receive %1 failed:\n%2").arg(enable ? QStringLiteral("enable") : QStringLiteral("disable"), output.trimmed());
}

QString VX6Backend::currentDownloadPath() const
{
    const QString cfgPath = resolveConfigPath();
    QFile configFile(cfgPath);
    if (configFile.open(QIODevice::ReadOnly)) {
        const QByteArray data = configFile.readAll();
        configFile.close();
        const QJsonDocument doc = QJsonDocument::fromJson(data);
        if (!doc.isNull() && doc.isObject()) {
            const QJsonObject root = doc.object();
            if (root.contains(QStringLiteral("node")) && root.value(QStringLiteral("node")).isObject()) {
                const QJsonObject nodeObj = root.value(QStringLiteral("node")).toObject();
                const QString downloadDir = nodeObj.value(QStringLiteral("download_dir")).toString().trimmed();
                if (!downloadDir.isEmpty()) {
                    const QDir dir(downloadDir);
                    if (dir.isAbsolute()) {
                        return QDir::cleanPath(downloadDir);
                    }
                    return QDir(QFileInfo(cfgPath).absolutePath()).absoluteFilePath(downloadDir);
                }
            }
        }
    }

    const QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (!defaultDir.isEmpty()) {
        return QDir::cleanPath(defaultDir);
    }
    return QDir::homePath() + QDir::separator() + QStringLiteral("Downloads");
}

QString VX6Backend::downloadedFilesHtml(const QString &downloadDir) const
{
    const QDir dir(downloadDir);
    if (!dir.exists()) {
        return QStringLiteral("<div class=\"output\">No download directory found: %1</div>").arg(downloadDir.toHtmlEscaped());
    }

    const QFileInfoList dirs = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    QStringList sections;
    for (const QFileInfo &folder : dirs) {
        if (!folder.fileName().endsWith(QStringLiteral("_vx6"))) {
            continue;
        }
        const QDir subdir(folder.filePath());
        const QFileInfoList files = subdir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot, QDir::Name);
        if (files.isEmpty()) {
            sections.append(QStringLiteral("<div class=\"hint\"><strong>%1</strong> — no received files yet.</div>").arg(folder.fileName().toHtmlEscaped()));
            continue;
        }
        QStringList rows;
        for (const QFileInfo &info : files) {
            rows.append(QStringLiteral("<li><strong>%1</strong> — %2</li>")
                .arg(info.fileName().toHtmlEscaped(), QString::number(info.size())));
        }
       sections.append(QStringLiteral(
    "<div class=\"panel\">"
    "<h3>Sender Group: %1</h3>"
    "%2"
    "</div>")
    .arg(folder.fileName().toHtmlEscaped(), rows.join(QString())));
    }

    if (sections.isEmpty()) {
        return QStringLiteral("<div class=\"output\">No sender-specific received folders found. Received files are stored in sender subdirectories ending with <code>_vx6</code>.</div>");
    }

    return sections.join(QString());
}

QString VX6Backend::filesPageHtml() const
{
    const QString status = receiveStatus();
    const QString configPath = resolveConfigPath();
    const QString downloadDir = currentDownloadPath();
    const QString filesHtml = downloadedFilesHtml(downloadDir);
   
    const QString body = QStringLiteral(
        "<div class=\"hint\">This page shows file receive/download status and quick file transfer actions.</div>"
        "<div class=\"section\"><h2>Receive Status</h2>%1</div>"
        "<div class=\"section\"><h2>Config Path</h2>%2</div>"
        "<div class=\"section\"><h2>Download Directory</h2>%3</div>"
        "<div class=\"section\"><h2>Downloaded Files</h2>%4</div>")
        .arg(commandBlock(status), commandBlock(configPath), commandBlock(downloadDir), filesHtml);
    return makePageShell("VX6 Files", "File transfer and receive status", body, "#ff9f43");
}
QString VX6Backend::transfersPageHtml() const
{
    const QString downloadDir = currentDownloadPath();
    const QString filesHtml = downloadedFilesHtml(downloadDir);

    const QString sentHtml = sentTransfersHtml();

    const QString body = QStringLiteral(
        "<div class=\"hint\">This page shows grouped VX6 file transfers and received files.</div>"
        "<div class=\"section\"><h2>Download Directory</h2>%1</div>"
        "<div class=\"section\"><h2>Transfer Groups</h2>%2</div>"
        "<div class=\"section\"><h2>Sent Transfers</h2>%3</div>")
        .arg(commandBlock(downloadDir), filesHtml, sentHtml);
    return makePageShell(
        "VX6 Transfers",
        "Grouped transfer history and received files",
        body,
        "#4cd137");
}
QString VX6Backend::sentTransfersHtml() const
{
    QFile historyFile(QDir::homePath() + "/.vx6-transfer-history.log");

    if (!historyFile.exists())
    {
        return QStringLiteral(
            "<div class=\"output\">No sent transfer history found.</div>");
    }

    if (!historyFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        return QStringLiteral(
            "<div class=\"output\">Failed to open sent transfer history.</div>");
    }

    QTextStream in(&historyFile);

    QStringList rows;

    while (!in.atEnd())
    {
        const QString line = in.readLine();
        const QStringList parts = line.split('|');

        if (parts.size() < 5)
        {
            continue;
        }

        const QString timestamp = parts[0];
        const QString status = parts[2];
        const QString fileName = parts[3];
        const QString target = parts[4];

        rows.append(QStringLiteral(
            "<div style=\"padding:14px; margin-bottom:12px; border:1px solid rgba(255,255,255,0.08); border-radius:14px; background:rgba(255,255,255,0.02);\">"
            "<div style=\"font-size:16px; font-weight:600; margin-bottom:8px;\">%1</div>"
            "<div class=\"hint\">Target: %2</div>"
            "<div class=\"hint\">Status: %3</div>"
            "<div class=\"hint\">Time: %4</div>"
            "</div>")
            .arg(
                fileName.toHtmlEscaped(),
                target.toHtmlEscaped(),
                status.toHtmlEscaped(),
                timestamp.toHtmlEscaped()));
    }

    if (rows.isEmpty())
    {
        return QStringLiteral(
            "<div class=\"output\">No sent transfers recorded yet.</div>");
    }

    return QStringLiteral("%1").arg(rows.join(QString()));
}

QString VX6Backend::stopHostedService(const QString &serviceName)
{
    const QString trimmed = serviceName.trimmed();
    if (trimmed.isEmpty()) {
        return QStringLiteral("service stop failed: empty name");
    }
    bool ok = false;
    const QString output = runVX6(QStringList{"service", "remove", "--name", trimmed}, &ok);
    if (ok) {
        const QString reloadOut = runVX6(QStringList{"reload"}, &ok);
        return output + QStringLiteral("\n") + reloadOut;
    }
    return output;
}

QString VX6Backend::lookupRaw(const QStringList &args, const QString &label) const
{
    bool ok = false;
    const QString output = runVX6(args, &ok);
    if (ok) {
        return label.isEmpty() ? output : QStringLiteral("[%1]\n%2").arg(label, output);
    }
    return output;
}

void VX6Backend::appendProcessOutput()
{
    const QString out = QString::fromUtf8(m_nodeProcess.readAllStandardOutput());
    const QString err = QString::fromUtf8(m_nodeProcess.readAllStandardError());
    const QString text = (out + err).trimmed();
    if (!text.isEmpty()) {
        emit logLine(text);
    }
}

void VX6Backend::updateNodeState()
{
    emit logLine(QStringLiteral("vx6 node state: %1").arg(nodeRunning() ? "running" : "stopped"));
}

QString VX6Backend::permissionPromptHtml() const
{
    const QString body = QStringLiteral(
        "<div class=\"notice warn\"><strong>First run permissions.</strong> "
        "Allow firewall/admin setup on Windows or macOS now so node publishing and discovery do not fail later.</div>"
        "<div class=\"section\"><h2>What to allow</h2>"
        "<div class=\"hint\">"
        "<ul>"
        "<li>Allow VX6 network access for the browser shell and node runtime.</li>"
        "<li>Allow the installer or first-run elevated prompt if your OS requests it.</li>"
        "<li>Keep the same binary path after install so firewall rules stay valid.</li>"
        "</ul>"
        "</div></div>");
    return makePageShell("VX6 Permissions", "Startup permissions and firewall guidance", body, "#ff7eb6");
}

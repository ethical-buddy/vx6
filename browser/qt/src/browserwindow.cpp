#include "browserwindow.h"

#include "vx6backend.h"
#include "vx6schemehandler.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDockWidget>
#include <QFileDialog>
#include <QScrollArea>
#include <QFormLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QStyle>
#include <QTabWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QSpinBox>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineUrlRequestInterceptor>
#include <QWebEngineView>
#include <QUrl>
#include <QGraphicsDropShadowEffect>
#include <QSpacerItem>
#include <QTabBar>
#include <QSizePolicy>
#include <QStylePainter>
#include <QPainter>
#include <QPainterPath>
#include <QMouseEvent>
#include <QEnterEvent>
#include <utility>


namespace
{
    class VX6TabWidget : public QTabWidget
    {
    public:
        using QTabWidget::QTabWidget;

        void installTabBar(QTabBar *tabBar)
        {
            setTabBar(tabBar);
        }
    };

    static const char *kBase =
        "* { font-family: 'Segoe UI', 'SF Pro Display', 'Helvetica Neue', sans-serif; }";

    class VX6RequestInterceptor : public QWebEngineUrlRequestInterceptor
    {
    public:
        explicit VX6RequestInterceptor(QObject *parent = nullptr)
            : QWebEngineUrlRequestInterceptor(parent) {}

        void interceptRequest(QWebEngineUrlRequestInfo &info) override
        {
            const QString scheme = info.requestUrl().scheme().toLower();
            if (scheme == "file" || scheme == "ftp" || scheme == "javascript")
                info.block(true);
        }
    };

    class VX6TabBar : public QTabBar
    {
    public:
        explicit VX6TabBar(QWidget *parent = nullptr) : QTabBar(parent)
        {
            setDrawBase(false);
            setExpanding(false);
            setElideMode(Qt::ElideRight);
        }

    protected:
        QSize tabSizeHint(int index) const override
        {
            QSize s = QTabBar::tabSizeHint(index);
            s.setWidth(s.width() + kBtnSize + kBtnMargin);
            return s;
        }

        void paintEvent(QPaintEvent *) override
        {
            QStylePainter p(this);
            for (int i = 0; i < count(); ++i)
            {
                QStyleOptionTab opt;
                initStyleOption(&opt, i);
                p.drawControl(QStyle::CE_TabBarTab, opt);
                drawCloseBtn(p, i);
            }
        }

        void mousePressEvent(QMouseEvent *e) override
        {
            if (e->button() == Qt::LeftButton)
            {
                for (int i = 0; i < count(); ++i)
                {
                    if (closeBtnRect(i).contains(e->pos()))
                    {
                        emit tabCloseRequested(i);
                        return;
                    }
                }
            }
            QTabBar::mousePressEvent(e);
        }

        void mouseMoveEvent(QMouseEvent *e) override
        {
            int hovered = -1;
            for (int i = 0; i < count(); ++i)
                if (closeBtnRect(i).contains(e->pos()))
                {
                    hovered = i;
                    break;
                }

            if (hovered != m_hoveredClose)
            {
                m_hoveredClose = hovered;
                update();
            }
            QTabBar::mouseMoveEvent(e);
        }

        void leaveEvent(QEvent *e) override
        {
            m_hoveredClose = -1;
            update();
            QTabBar::leaveEvent(e);
        }

    private:
        static constexpr int kBtnSize = 16;
        static constexpr int kBtnMargin = 6;
        static constexpr int kCross = 4;

        int m_hoveredClose = -1;

        QRect closeBtnRect(int index) const
        {
            QRect r = tabRect(index);
            int cx = r.right() - kBtnMargin - kBtnSize / 2;
            int cy = r.center().y();
            return QRect(cx - kBtnSize / 2, cy - kBtnSize / 2, kBtnSize, kBtnSize);
        }

        void drawCloseBtn(QPainter &p, int index)
        {
            const bool hovered = (index == m_hoveredClose);
            QRect br = closeBtnRect(index);

            p.save();
            p.setRenderHint(QPainter::Antialiasing);

            if (hovered)
            {
                p.setPen(Qt::NoPen);
                p.setBrush(QColor(0xfb, 0x54, 0x2b, 200));
                p.drawRoundedRect(br, 4, 4);
            }

            QColor lineColor = hovered ? QColor("#ffffff") : QColor("#8890a4");
            QPen pen(lineColor, 1.5f, Qt::SolidLine, Qt::RoundCap);
            p.setPen(pen);

            QPointF c = br.center();
            p.drawLine(QPointF(c.x() - kCross, c.y() - kCross),
                       QPointF(c.x() + kCross, c.y() + kCross));
            p.drawLine(QPointF(c.x() + kCross, c.y() - kCross),
                       QPointF(c.x() - kCross, c.y() + kCross));

            p.restore();
        }
    };

    QPushButton *makeSideBtn(const QString &label, QWidget *parent)
    {
        auto *btn = new QPushButton(label, parent);
        btn->setCursor(Qt::PointingHandCursor);
        btn->setStyleSheet(
            "QPushButton {"
            "  background: #1c2030;"
            "  color: #c5cad8;"
            "  border: 1px solid rgba(255,255,255,0.06);"
            "  border-radius: 8px;"
            "  padding: 8px 14px;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "  text-align: left;"
            "}"
            "QPushButton:hover {"
            "  background: #252b3b;"
            "  color: #e8eaf0;"
            "  border-color: rgba(251,84,43,0.45);"
            "}"
            "QPushButton:pressed {"
            "  background: #fb542b;"
            "  color: #ffffff;"
            "  border-color: #fb542b;"
            "}");
        return btn;
    }
}

// browser window
BrowserWindow::BrowserWindow(const QString &vx6Binary,
                             const QString &configPath,
                             QWidget *parent)
    : QMainWindow(parent),
      m_backend(new VX6Backend(vx6Binary, configPath, this)),
      m_profile(new QWebEngineProfile("vx6-browser", this)),
      m_tabs(nullptr), m_address(nullptr),
      m_controlDock(nullptr), m_ipv6Field(nullptr), m_nodeNameField(nullptr), m_nodeIdField(nullptr),
      m_initNodeNameField(nullptr), m_connectServiceField(nullptr),
      m_renameField(nullptr), m_lookupField(nullptr), m_hostNameField(nullptr), m_hostPortField(nullptr), m_lookupResult(nullptr),
      m_logView(nullptr), m_logDock(nullptr), m_shortcuts(nullptr)
{
    setWindowTitle("VX6");
    resize(1520, 960);
    setStyleSheet(kBase);

    setStyleSheet(QString(kBase) +
                  "QMainWindow { background: #12151a; }"
                  "QMainWindow::separator { background: rgba(255,255,255,0.04); width: 1px; }");

    m_profile->setHttpUserAgent("VX6/1.0");
    m_profile->setUrlRequestInterceptor(new VX6RequestInterceptor(m_profile));
    m_profile->installUrlSchemeHandler(
        QByteArrayLiteral("vx6"),
        new VX6SchemeHandler(m_backend, m_profile));

    buildUi();
    buildToolbar();
    buildControlDock();
    buildDock();
    registerBrowserCallbacks();
    maybeShowPermissionPrompt();
    
    // Ensure vx6 binary exists (build if needed)
    appendLog("Initializing VX6...");
    appendLog(m_backend->ensureVx6Binary());
    
    // Auto-start the node on browser launch
    if (!m_backend->nodeRunning()) {
        appendLog(m_backend->startNode());
    }
    
    openHome();
}

// ui shell
void BrowserWindow::buildUi()
{
    auto *tabs = new VX6TabWidget(this);
    m_tabs = tabs;
    m_tabs->setDocumentMode(true);
    m_tabs->setTabsClosable(true);
    m_tabs->setMovable(true);
    m_tabs->setElideMode(Qt::ElideRight);

    auto *customBar = new VX6TabBar(m_tabs);
    tabs->installTabBar(customBar);

    m_tabs->setStyleSheet(
        "QTabWidget::pane {"
        "  border: none;"
        "  background: #12151a;"
        "  margin-top: 0px;"
        "}"
        "QTabBar {"
        "  background: #0e1118;"
        "  border-bottom: 1px solid rgba(255,255,255,0.05);"
        "  qproperty-drawBase: 0;"
        "}"
        "QTabBar::tab {"
        "  background: transparent;"
        "  color: #8890a4;"
        "  border: none;"
        "  border-right: 1px solid rgba(255,255,255,0.04);"
        "  padding: 0 38px 0 16px;"
        "  height: 40px;"
        "  min-width: 120px;"
        "  max-width: 210px;"
        "  font-size: 12px;"
        "  font-weight: 500;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "  background: rgba(255,255,255,0.04);"
        "  color: #c5cad8;"
        "}"
        "QTabBar::tab:selected {"
        "  background: #12151a;"
        "  color: #e8eaf0;"
        "  border-bottom: 2px solid #ffb19e;"
        "  font-weight: 600;"
        "}"
        "QTabBar::close-button { image: none; width: 0; height: 0; padding: 0; border: none; }");

    connect(m_tabs, &QTabWidget::currentChanged, this, &BrowserWindow::currentTabChanged);
    connect(customBar, &QTabBar::tabCloseRequested, this, &BrowserWindow::closeTab);
    setCentralWidget(m_tabs);
}

// navigation toolbar
void BrowserWindow::buildToolbar()
{
    auto *toolbar = new QToolBar("Navigation", this);
    toolbar->setMovable(false);
    toolbar->setFloatable(false);
    toolbar->setIconSize(QSize(16, 16));
    toolbar->setContentsMargins(0, 0, 0, 0);
        toolbar->setStyleSheet(
            "QToolBar {"
            "  background: #0e1118;"
            "  border: none;"
            "  border-bottom: 1px solid rgba(255,255,255,0.05);"
            "  padding: 6px 10px;"
            "  spacing: 4px;"
            "}"
            "QToolButton {"
            "  background: transparent;"
            "  color: #8890a4;"
            "  border: none;"
            "  border-radius: 7px;"
            "  padding: 6px 7px;"
            "  min-width: 28px;"
            "}"
            "QToolButton:hover { background: rgba(255,255,255,0.07); color: #e8eaf0; }"
            "QToolButton:pressed { background: rgba(255,255,255,0.11); }"
            "QPushButton {"
            "  background: rgba(255,255,255,0.05);"
            "  color: #c5cad8;"
            "  border: 1px solid rgba(255,255,255,0.07);"
            "  border-radius: 8px;"
            "  padding: 5px 13px;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(255,255,255,0.09);"
            "  color: #e8eaf0;"
            "  border-color: rgba(251,84,43,0.4);"
            "}"
            "QPushButton:pressed { background: #fb542b; color: #fff; border-color: #fb542b; }"
            "QLineEdit {"
            "  background: #1c2030;"
            "  color: #e8eaf0;"
            "  border: 1px solid rgba(255,255,255,0.07);"
            "  border-radius: 17px;"
            "  padding: 6px 36px 6px 16px;"
            "  font-size: 13px;"
            "  min-width: 480px;"
            "  selection-background-color: #fb542b;"
            "}"
            "QLineEdit:focus {"
            "  border-color: rgb(255, 93, 52);"
            "  background: #252b3b;"
            "}"
            "QLineEdit::clear-button {"
            "  padding-right: 16px;"
            "  margin-right: 24px;"
            "}");

    addToolBar(toolbar);

    QAction *back = toolbar->addAction(style()->standardIcon(QStyle::SP_ArrowBack), "Back");
    QAction *forward = toolbar->addAction(style()->standardIcon(QStyle::SP_ArrowForward), "Forward");
    QAction *reload = toolbar->addAction(style()->standardIcon(QStyle::SP_BrowserReload), "Reload");

    toolbar->addSeparator();

    QAction *home = toolbar->addAction(style()->standardIcon(QStyle::SP_DirHomeIcon), "Home");

    auto *spacerL = new QWidget();
    spacerL->setFixedWidth(6);
    toolbar->addWidget(spacerL);

    m_address = new QLineEdit(this);
    m_address->setPlaceholderText("Search or enter  vx6://  •  http://  •  https://  •  localhost");
    m_address->setClearButtonEnabled(true);
    toolbar->addWidget(m_address);

    auto *spacerR = new QWidget();
    spacerR->setFixedWidth(6);
    toolbar->addWidget(spacerR);

    auto *bookmarkBtn = new QPushButton("★", this);
    bookmarkBtn->setToolTip("Bookmark");
    bookmarkBtn->setFixedSize(32, 32);
    bookmarkBtn->setStyleSheet(
        "QPushButton { background: transparent; color: #8890a4; border: none; border-radius: 7px;"
        "  font-size: 15px; padding: 0; }"
        "QPushButton:hover { background: rgba(255,255,255,0.07); color: #f4c430; }"
        "QPushButton:pressed { color: #fb542b; }");
    toolbar->addWidget(bookmarkBtn);

    auto *newTabBtn = new QPushButton("+", this);
    newTabBtn->setToolTip("New Tab");
    newTabBtn->setFixedSize(32, 32);
    newTabBtn->setStyleSheet(
        "QPushButton { background: transparent; color: #8890a4; border: none; border-radius: 7px;"
        "  font-size: 18px; font-weight: 300; padding: 0; }"
        "QPushButton:hover { background: rgba(255,255,255,0.07); color: #e8eaf0; }"
        "QPushButton:pressed { background: #fb542b; color: #fff; }");
    toolbar->addWidget(newTabBtn);

    auto *logsBtn = new QPushButton("⌘", this);
    logsBtn->setToolTip("Toggle Side Panel");
    logsBtn->setFixedSize(32, 32);
    logsBtn->setStyleSheet(
        "QPushButton { background: transparent; color: #8890a4; border: none; border-radius: 7px;"
        "  font-size: 15px; padding: 0; }"
        "QPushButton:hover { background: rgba(255,255,255,0.07); color: #e8eaf0; }"
        "QPushButton:pressed { background: rgba(255,255,255,0.11); }");
    toolbar->addWidget(logsBtn);

    connect(back, &QAction::triggered, this, [this]
            { if (auto *v = currentView()) v->back(); });
    connect(forward, &QAction::triggered, this, [this]
            { if (auto *v = currentView()) v->forward(); });
    connect(reload, &QAction::triggered, this, [this]
            {
        if (auto *v = currentView()) v->reload();
        refreshStatus(); });
    connect(home, &QAction::triggered, this, &BrowserWindow::openHome);
    connect(bookmarkBtn, &QPushButton::clicked, this, &BrowserWindow::bookmarkCurrent);
    connect(newTabBtn, &QPushButton::clicked, this, &BrowserWindow::newTab);
    connect(logsBtn, &QPushButton::clicked, this, &BrowserWindow::toggleLogs);
    connect(m_address, &QLineEdit::returnPressed, this, &BrowserWindow::openAddress);
}

// left control dock
void BrowserWindow::buildControlDock()
{
    m_controlDock = new QDockWidget(this);
    m_controlDock->setWindowTitle("Control");
    m_controlDock->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    m_controlDock->setFeatures(QDockWidget::DockWidgetClosable | QDockWidget::DockWidgetMovable);
    m_controlDock->setMinimumWidth(360);
    m_controlDock->setMaximumWidth(460);

    m_controlDock->setStyleSheet(
        "QDockWidget { color: #e8eaf0; font-size: 12px; font-weight: 600; }"
        "QDockWidget::title { background: #0e1118; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px 12px; }"
        "QDockWidget::close-button { background: transparent; border: none; image: none; }");

    auto *scrollArea = new QScrollArea(m_controlDock);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");

    auto *root = new QWidget();
    root->setStyleSheet("QWidget { background: #12151a; color: #e8eaf0; }");

    auto *outer = new QVBoxLayout(root);
    outer->setContentsMargins(14, 14, 14, 14);
    outer->setSpacing(12);

    auto makeFrame = [&](const QString &title) {
        auto *frame = new QFrame(root);
        frame->setStyleSheet(
            "QFrame { background: #151b28; border: 1px solid rgba(255,255,255,0.06); border-radius: 16px; }");
        auto *lay = new QVBoxLayout(frame);
        lay->setContentsMargins(14, 12, 14, 12);
        lay->setSpacing(8);
        auto *lbl = new QLabel(title, frame);
        lbl->setStyleSheet("QLabel { color: #9ca7bd; font-size: 10px; font-weight: 800; letter-spacing: 1.4px; }");
        lay->addWidget(lbl);
        return std::pair<QFrame *, QVBoxLayout *>(frame, lay);
    };

    auto [netFrame, netLay] = makeFrame("NETWORK");
    auto *ipv6Row = new QWidget(netFrame);
    auto *ipv6RowLay = new QHBoxLayout(ipv6Row);
    ipv6RowLay->setContentsMargins(0, 0, 0, 0);
    ipv6RowLay->setSpacing(8);
    m_ipv6Field = new QLineEdit(ipv6Row);
    m_ipv6Field->setReadOnly(true);
    m_ipv6Field->setPlaceholderText("Current IPv6 / advertise address");
    m_ipv6Field->setStyleSheet(
        "QLineEdit { background: #0e1118; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 8px 10px; color: #e8eaf0; }");
    auto *copyIpv6 = makeSideBtn("Copy", ipv6Row);
    ipv6RowLay->addWidget(m_ipv6Field, 1);
    ipv6RowLay->addWidget(copyIpv6);
    netLay->addWidget(ipv6Row);

    m_nodeNameField = new QLineEdit(netFrame);
    m_nodeNameField->setReadOnly(true);
    m_nodeNameField->setPlaceholderText("Node name");
    m_nodeNameField->setStyleSheet(m_ipv6Field->styleSheet());
    netLay->addWidget(m_nodeNameField);

    m_nodeIdField = new QLineEdit(netFrame);
    m_nodeIdField->setReadOnly(true);
    m_nodeIdField->setPlaceholderText("Node ID");
    m_nodeIdField->setStyleSheet(m_ipv6Field->styleSheet());
    netLay->addWidget(m_nodeIdField);

    auto *refreshPanel = makeSideBtn("↺  Refresh panel", netFrame);
    netLay->addWidget(refreshPanel);
    outer->addWidget(netFrame);

    auto [initFrame, initLay] = makeFrame("INITIALIZE NODE");
    m_initNodeNameField = new QLineEdit(initFrame);
    m_initNodeNameField->setPlaceholderText("New node name");
    m_initNodeNameField->setStyleSheet(m_ipv6Field->styleSheet());
    initLay->addWidget(m_initNodeNameField);
    auto *initBtn = makeSideBtn("Init New Node", initFrame);
    auto *initHint = new QLabel("Creates a new node with fresh keys. This will stop the current node.", initFrame);
    initHint->setWordWrap(true);
    initHint->setStyleSheet("QLabel { color: #7f889b; font-size: 11px; }");
    initLay->addWidget(initBtn);
    initLay->addWidget(initHint);
    outer->addWidget(initFrame);

    auto [connectFrame, connectLay] = makeFrame("CONNECT");
    m_connectServiceField = new QLineEdit(connectFrame);
    m_connectServiceField->setPlaceholderText("Service name or address");
    m_connectServiceField->setStyleSheet(m_ipv6Field->styleSheet());
    connectLay->addWidget(m_connectServiceField);
    auto *connectBtn = makeSideBtn("Connect", connectFrame);
    auto *connectHint = new QLabel("Connect to a VX6 service by name or address.", connectFrame);
    connectHint->setWordWrap(true);
    connectHint->setStyleSheet("QLabel { color: #7f889b; font-size: 11px; }");
    connectLay->addWidget(connectBtn);
    connectLay->addWidget(connectHint);
    outer->addWidget(connectFrame);

    auto [fileFrame, fileLay] = makeFrame("FILE TRANSFER");
    m_sendFileField = new QLineEdit(fileFrame);
    m_sendFileField->setPlaceholderText("File path e.g. /home/user/Downloads/sample.txt");
    m_sendFileField->setStyleSheet(m_ipv6Field->styleSheet());
    fileLay->addWidget(m_sendFileField);
    auto *fileRow = new QWidget(fileFrame);
    auto *fileRowLay = new QHBoxLayout(fileRow);
    fileRowLay->setContentsMargins(0, 0, 0, 0);
    fileRowLay->setSpacing(8);
    auto *browseBtn = makeSideBtn("Browse", fileRow);
    auto *sendBtn = makeSideBtn("Send File", fileRow);
    fileRowLay->addWidget(browseBtn);
    fileRowLay->addWidget(sendBtn);
    fileLay->addWidget(fileRow);
    m_sendTargetField = new QLineEdit(fileFrame);
    m_sendTargetField->setPlaceholderText("Receiver name or address e.g. alice or [ipv6]:4242");
    m_sendTargetField->setStyleSheet(m_ipv6Field->styleSheet());
    fileLay->addWidget(m_sendTargetField);
    auto *receiveStatusBtn = makeSideBtn("Receive Status", fileFrame);
    fileLay->addWidget(receiveStatusBtn);
    m_toggleReceiveBtn = makeSideBtn("Toggle Receive", fileFrame);
    fileLay->addWidget(m_toggleReceiveBtn);
    auto *fileHint = new QLabel("Use a local file path and target name or address. For direct send, use [ipv6]:4242.", fileFrame);
    fileHint->setWordWrap(true);
    fileHint->setStyleSheet("QLabel { color: #7f889b; font-size: 11px; }");
    fileLay->addWidget(fileHint);
    outer->addWidget(fileFrame);

    auto [renameFrame, renameLay] = makeFrame("NODE NAME");
    m_renameField = new QLineEdit(renameFrame);
    m_renameField->setPlaceholderText("Enter a new node name");
    m_renameField->setStyleSheet(m_ipv6Field->styleSheet());
    renameLay->addWidget(m_renameField);
    auto *renameRow = new QWidget(renameFrame);
    auto *renameRowLay = new QHBoxLayout(renameRow);
    renameRowLay->setContentsMargins(0, 0, 0, 0);
    renameRowLay->setSpacing(8);
    auto *renameBtn = makeSideBtn("Rename", renameRow);
    auto *renameHelp = new QLabel("Name changes probe the network first.", renameRow);
    renameHelp->setStyleSheet("QLabel { color: #7f889b; font-size: 11px; }");
    renameRowLay->addWidget(renameBtn);
    renameRowLay->addWidget(renameHelp, 1);
    renameLay->addWidget(renameRow);
    outer->addWidget(renameFrame);

    auto [lookupFrame, lookupLay] = makeFrame("LOOKUP");
    m_lookupField = new QLineEdit(lookupFrame);
    m_lookupField->setPlaceholderText("Search service, node, or hidden invite");
    m_lookupField->setStyleSheet(m_ipv6Field->styleSheet());
    lookupLay->addWidget(m_lookupField);
    auto *lookupButtons = new QWidget(lookupFrame);
    auto *lookupButtonsLay = new QHBoxLayout(lookupButtons);
    lookupButtonsLay->setContentsMargins(0, 0, 0, 0);
    lookupButtonsLay->setSpacing(8);
    auto *serviceBtn = makeSideBtn("Service", lookupButtons);
    auto *nodeBtn = makeSideBtn("Node", lookupButtons);
    auto *hiddenBtn = makeSideBtn("Hidden", lookupButtons);
    lookupButtonsLay->addWidget(serviceBtn);
    lookupButtonsLay->addWidget(nodeBtn);
    lookupButtonsLay->addWidget(hiddenBtn);
    lookupLay->addWidget(lookupButtons);
    m_lookupResult = new QTextEdit(lookupFrame);
    m_lookupResult->setReadOnly(true);
    m_lookupResult->setPlaceholderText("Lookup results appear here…");
    m_lookupResult->setStyleSheet(
        "QTextEdit { background: #0e1118; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 10px; color: #cdd6e6; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 11px; }");
    m_lookupResult->setMinimumHeight(150);
    lookupLay->addWidget(m_lookupResult, 1);
    outer->addWidget(lookupFrame, 1);

    auto [hostFrame, hostLay] = makeFrame("SERVICE HOSTING");
    m_hostNameField = new QLineEdit(hostFrame);
    m_hostNameField->setPlaceholderText("Service name");
    m_hostNameField->setStyleSheet(m_ipv6Field->styleSheet());
    hostLay->addWidget(m_hostNameField);

    auto *hostRow = new QWidget(hostFrame);
    auto *hostRowLay = new QHBoxLayout(hostRow);
    hostRowLay->setContentsMargins(0, 0, 0, 0);
    hostRowLay->setSpacing(8);
    m_hostPortField = new QSpinBox(hostRow);
    m_hostPortField->setRange(1, 65535);
    m_hostPortField->setValue(8080);
    m_hostPortField->setStyleSheet(
        "QSpinBox { background: #0e1118; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 8px 10px; color: #e8eaf0; }");
    auto *forwardBtn = makeSideBtn("Forward", hostRow);
    auto *stopBtn = makeSideBtn("Stop", hostRow);
    hostRowLay->addWidget(m_hostPortField);
    hostRowLay->addWidget(forwardBtn);
    hostRowLay->addWidget(stopBtn);
    hostLay->addWidget(hostRow);
    auto *hostHint = new QLabel("Forwards local 127.0.0.1:PORT as a VX6 service. Stop removes it.", hostFrame);
    hostHint->setWordWrap(true);
    hostHint->setStyleSheet("QLabel { color: #7f889b; font-size: 11px; }");
    hostLay->addWidget(hostHint);
    outer->addWidget(hostFrame);

    auto *spacer = new QWidget(root);
    spacer->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    outer->addWidget(spacer, 1);

    root->setLayout(outer);
    scrollArea->setWidget(root);
    m_controlDock->setWidget(scrollArea);
    addDockWidget(Qt::LeftDockWidgetArea, m_controlDock);

    connect(copyIpv6, &QPushButton::clicked, this, &BrowserWindow::copyCurrentIpv6);
    connect(refreshPanel, &QPushButton::clicked, this, &BrowserWindow::refreshControlPanel);
    connect(initBtn, &QPushButton::clicked, this, &BrowserWindow::initializeNodeFromPanel);
    connect(connectBtn, &QPushButton::clicked, this, &BrowserWindow::connectServiceFromPanel);
    connect(renameBtn, &QPushButton::clicked, this, &BrowserWindow::renameNodeFromPanel);
    connect(serviceBtn, &QPushButton::clicked, this, &BrowserWindow::lookupServiceFromPanel);
    connect(nodeBtn, &QPushButton::clicked, this, &BrowserWindow::lookupNodeFromPanel);
    connect(hiddenBtn, &QPushButton::clicked, this, &BrowserWindow::lookupHiddenFromPanel);
    connect(forwardBtn, &QPushButton::clicked, this, &BrowserWindow::hostServiceFromPanel);
    connect(stopBtn, &QPushButton::clicked, this, &BrowserWindow::stopHostedServiceFromPanel);
    connect(browseBtn, &QPushButton::clicked, this, &BrowserWindow::chooseFileFromPanel);
    connect(sendBtn, &QPushButton::clicked, this, &BrowserWindow::sendFileFromPanel);
    connect(receiveStatusBtn, &QPushButton::clicked, this, &BrowserWindow::showFileTransferPage);
    connect(m_toggleReceiveBtn, &QPushButton::clicked, this, &BrowserWindow::toggleReceiveFromPanel);
    connect(m_lookupField, &QLineEdit::returnPressed, this, &BrowserWindow::lookupServiceFromPanel);
    connect(m_renameField, &QLineEdit::returnPressed, this, &BrowserWindow::renameNodeFromPanel);
    connect(m_hostNameField, &QLineEdit::returnPressed, this, &BrowserWindow::hostServiceFromPanel);
    connect(m_initNodeNameField, &QLineEdit::returnPressed, this, &BrowserWindow::initializeNodeFromPanel);
    connect(m_connectServiceField, &QLineEdit::returnPressed, this, &BrowserWindow::connectServiceFromPanel);
    connect(m_sendTargetField, &QLineEdit::returnPressed, this, &BrowserWindow::sendFileFromPanel);
    connect(m_controlDock, &QDockWidget::visibilityChanged, this, [this](bool visible)
            {
                if (visible)
                    refreshControlPanel();
            });

    refreshControlPanel();
}

// side panel dock
void BrowserWindow::buildDock()
{
    m_logDock = new QDockWidget(this);
    m_logDock->setWindowTitle("Panel");
    m_logDock->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    m_logDock->setFeatures(QDockWidget::DockWidgetClosable | QDockWidget::DockWidgetMovable);
    m_logDock->setMinimumWidth(260);
    m_logDock->setMaximumWidth(360);

    m_logDock->setStyleSheet(
        "QDockWidget {"
        "  color: #e8eaf0;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "}"
        "QDockWidget::title {"
        "  background: #0e1118;"
        "  border-bottom: 1px solid rgba(255,255,255,0.05);"
        "  padding: 8px 12px;"
        "  text-align: left;"
        "}"
        "QDockWidget::close-button {"
        "  background: transparent;"
        "  border: none;"
        "  border-radius: 4px;"
        "  padding: -6px;"
        "  image: url('data:image/svg+xml;utf8,<svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M4 4L12 12M12 4L4 12\" stroke=\"%238890a4\" stroke-width=\"1.5\" stroke-linecap=\"round\"/></svg>');"
        "}"
        "QDockWidget::close-button:hover {"
        "  background: rgba(251,84,43,0.78);"
        "  image: url('data:image/svg+xml;utf8,<svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M4 4L12 12M12 4L4 12\" stroke=\"%23ffffff\" stroke-width=\"1.5\" stroke-linecap=\"round\"/></svg>');"
        "}");

    auto *dockBody = new QWidget(m_logDock);
    dockBody->setStyleSheet("QWidget { background: #12151a; }");

    auto *layout = new QVBoxLayout(dockBody);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(6);

    auto makeSection = [&](const QString &text)
    {
        auto *lbl = new QLabel(text, dockBody);
        lbl->setStyleSheet(
            "QLabel { color: #4e5668; font-size: 10px; font-weight: 700;"
            "  letter-spacing: 1.2px; text-transform: uppercase;"
            "  padding: 10px 2px 4px 2px; background: transparent; }");
        return lbl;
    };

    layout->addWidget(makeSection("Node"));

    auto *btnGrid = new QWidget(dockBody);
    auto *btnLayout = new QHBoxLayout(btnGrid);
    btnLayout->setContentsMargins(0, 0, 0, 0);
    btnLayout->setSpacing(6);

    auto *startBtn = makeSideBtn("▶  Start", btnGrid);
    auto *stopBtn = makeSideBtn("■  Stop", btnGrid);
    auto *reloadBtn = makeSideBtn("↺  Reload", btnGrid);
    btnLayout->addWidget(startBtn);
    btnLayout->addWidget(stopBtn);
    btnLayout->addWidget(reloadBtn);
    layout->addWidget(btnGrid);

    auto *statusBtn = makeSideBtn("◎  Refresh Status", dockBody);
    auto *permBtn = makeSideBtn("🔒  Firewall / Permissions", dockBody);
    layout->addWidget(statusBtn);
    layout->addWidget(permBtn);

    auto *line = new QFrame(dockBody);
    line->setFrameShape(QFrame::HLine);
    line->setStyleSheet("QFrame { color: rgba(255,255,255,0.05); margin: 4px 0; }");
    layout->addWidget(line);

    layout->addWidget(makeSection("Quick Nav"));

    m_shortcuts = new QListWidget(dockBody);
    m_shortcuts->addItems({
        "vx6://status",
        "vx6://dht",
        "vx6://registry",
        "vx6://services",
        "vx6://peers",
        "vx6://identity",
        "vx6://files",
        "vx6://permissions",
        "vx6://transfers"
    });
    m_shortcuts->setFocusPolicy(Qt::NoFocus);
    m_shortcuts->setStyleSheet(
        "QListWidget {"
        "  background: #1c2030;"
        "  color: #8890a4;"
        "  border: 1px solid rgba(255,255,255,0.06);"
        "  border-radius: 10px;"
        "  padding: 4px;"
        "  font-size: 12px;"
        "  outline: none;"
        "}"
        "QListWidget::item {"
        "  padding: 7px 10px;"
        "  border-radius: 6px;"
        "}"
        "QListWidget::item:hover {"
        "  background: rgba(255,255,255,0.05);"
        "  color: #c5cad8;"
        "}"
        "QListWidget::item:selected {"
        "  background: rgba(251,84,43,0.18);"
        "  color: #fb8f6f;"
        "}");
    layout->addWidget(m_shortcuts, 1);

    layout->addWidget(makeSection("Activity"));

    m_logView = new QTextEdit(dockBody);
    m_logView->setReadOnly(true);
    m_logView->setPlaceholderText("Runtime and navigation activity…");
    m_logView->setStyleSheet(
        "QTextEdit {"
        "  background: #0e1118;"
        "  color: #606878;"
        "  border: 1px solid rgba(255,255,255,0.05);"
        "  border-radius: 10px;"
        "  padding: 8px 10px;"
        "  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;"
        "  font-size: 11px;"
        "  line-height: 1.6;"
        "}"
        "QTextEdit:focus { border-color: rgba(251,84,43,0.3); }"
        "QScrollBar:vertical {"
        "  background: transparent; width: 5px; margin: 0;"
        "}"
        "QScrollBar::handle:vertical {"
        "  background: rgba(255,255,255,0.12); border-radius: 3px; min-height: 24px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }");
    layout->addWidget(m_logView, 2);

    dockBody->setLayout(layout);
    m_logDock->setWidget(dockBody);
    addDockWidget(Qt::RightDockWidgetArea, m_logDock);

    connect(startBtn, &QPushButton::clicked, this, &BrowserWindow::startNode);
    connect(stopBtn, &QPushButton::clicked, this, &BrowserWindow::stopNode);
    connect(reloadBtn, &QPushButton::clicked, this, &BrowserWindow::reloadNode);
    connect(statusBtn, &QPushButton::clicked, this, &BrowserWindow::refreshStatus);
    connect(permBtn, &QPushButton::clicked, this, [this]
            { navigateTo("vx6://permissions", false); });
    connect(m_shortcuts, &QListWidget::itemDoubleClicked, this,
            [this](QListWidgetItem *item)
            { navigateTo(item->text(), false); });
}

void BrowserWindow::refreshControlPanel()
{
    const QString ipv6 = m_backend->currentAdvertiseAddr();
    const QString name = m_backend->currentNodeName();
    const QString nodeId = m_backend->currentNodeID();

    if (m_ipv6Field) {
        m_ipv6Field->setText(ipv6.isEmpty() ? QStringLiteral("(not published yet)") : ipv6);
    }
    if (m_nodeNameField) {
        m_nodeNameField->setText(name.isEmpty() ? QStringLiteral("(unnamed)") : name);
    }
    if (m_nodeIdField) {
        m_nodeIdField->setText(nodeId.isEmpty() ? QStringLiteral("(identity unavailable)") : nodeId);
    }
    if (m_toggleReceiveBtn) {
        const bool enabled = m_backend->receiveEnabled();
        m_toggleReceiveBtn->setText(enabled ? QStringLiteral("Disable Receive") : QStringLiteral("Enable Receive"));
    }
}

void BrowserWindow::copyCurrentIpv6()
{
    refreshControlPanel();
    const QString text = m_ipv6Field ? m_ipv6Field->text().trimmed() : QString();
    if (text.isEmpty() || text.startsWith('(')) {
        appendLog("no current IPv6 available to copy");
        return;
    }
    QApplication::clipboard()->setText(text);
    appendLog(QString("copied current IPv6: %1").arg(text));
}

void BrowserWindow::renameNodeFromPanel()
{
    if (!m_renameField) {
        return;
    }
    const QString name = m_renameField->text().trimmed();
    if (name.isEmpty()) {
        appendLog("node rename skipped: empty name");
        return;
    }
    appendLog(QString("renaming node to %1…").arg(name));
    appendLog(m_backend->renameNode(name));
    refreshControlPanel();
    refreshStatus();
    if (currentView()) {
        currentView()->setUrl(QUrl("vx6://identity"));
    }
}

void BrowserWindow::lookupServiceFromPanel()
{
    if (!m_lookupField) {
        return;
    }
    const QString query = m_lookupField->text().trimmed();
    if (query.isEmpty()) {
        appendLog("service lookup skipped: empty query");
        return;
    }
    appendLog(QString("lookup service: %1").arg(query));
    const QString result = m_backend->lookupRaw(QStringList{"debug", "dht-get", "--service", query}, "service lookup");
    if (m_lookupResult) {
        m_lookupResult->setPlainText(result);
    }
    appendLog(result.trimmed());
    navigateTo(QStringLiteral("vx6://service/%1").arg(QString::fromUtf8(QUrl::toPercentEncoding(query))), false);
}

void BrowserWindow::lookupNodeFromPanel()
{
    if (!m_lookupField) {
        return;
    }
    const QString query = m_lookupField->text().trimmed();
    if (query.isEmpty()) {
        appendLog("node lookup skipped: empty query");
        return;
    }
    appendLog(QString("lookup node: %1").arg(query));
    const QString result = m_backend->lookupRaw(QStringList{"debug", "dht-get", "--node", query}, "node lookup");
    if (m_lookupResult) {
        m_lookupResult->setPlainText(result);
    }
    appendLog(result.trimmed());
    navigateTo(QStringLiteral("vx6://node/%1").arg(QString::fromUtf8(QUrl::toPercentEncoding(query))), false);
}

void BrowserWindow::lookupHiddenFromPanel()
{
    if (!m_lookupField) {
        return;
    }
    const QString query = m_lookupField->text().trimmed();
    if (query.isEmpty()) {
        appendLog("hidden lookup skipped: empty query");
        return;
    }
    appendLog(QString("lookup hidden service: %1").arg(query));
    const QString result = m_backend->lookupRaw(QStringList{"debug", "dht-get", "--service", query}, "hidden lookup");
    if (m_lookupResult) {
        m_lookupResult->setPlainText(result);
    }
    appendLog(result.trimmed());
    navigateTo(QStringLiteral("vx6://service/%1").arg(QString::fromUtf8(QUrl::toPercentEncoding(query))), false);
}

void BrowserWindow::hostServiceFromPanel()
{
    if (!m_hostNameField || !m_hostPortField) {
        return;
    }
    const QString name = m_hostNameField->text().trimmed();
    const int port = m_hostPortField->value();
    if (name.isEmpty()) {
        appendLog("service hosting skipped: empty service name");
        return;
    }
    appendLog(QString("hosting service %1 on port %2…").arg(name).arg(port));
    const QString result = m_backend->hostService(name, port);
    appendLog(result.trimmed());
    refreshControlPanel();
    refreshStatus();
    navigateTo("vx6://services", false);
}

void BrowserWindow::stopHostedServiceFromPanel()
{
    if (!m_hostNameField) {
        return;
    }
    const QString name = m_hostNameField->text().trimmed();
    if (name.isEmpty()) {
        appendLog("service stop skipped: empty service name");
        return;
    }
    appendLog(QString("stopping hosted service %1…").arg(name));
    const QString result = m_backend->stopHostedService(name);
    appendLog(result.trimmed());
    refreshControlPanel();
    refreshStatus();
    navigateTo("vx6://services", false);
}

void BrowserWindow::initializeNodeFromPanel()
{
    if (!m_initNodeNameField) {
        return;
    }
    const QString name = m_initNodeNameField->text().trimmed();
    if (name.isEmpty()) {
        appendLog("node init skipped: empty node name");
        return;
    }
    appendLog(QString("initializing new node as %1…").arg(name));
    const QString result = m_backend->initializeNode(name);
    appendLog(result.trimmed());
    m_initNodeNameField->clear();
    refreshControlPanel();
    refreshStatus();
}

void BrowserWindow::connectServiceFromPanel()
{
    if (!m_connectServiceField) {
        return;
    }
    const QString target = m_connectServiceField->text().trimmed();
    if (target.isEmpty()) {
        appendLog("connect skipped: empty service name or address");
        return;
    }
    appendLog(QString("connecting to %1…").arg(target));
    const QString result = m_backend->connectService(target);
    appendLog(result.trimmed());
    m_connectServiceField->clear();
}

void BrowserWindow::chooseFileFromPanel()
{
    const QString filePath = QFileDialog::getOpenFileName(this, "Choose file to send", QString(), QStringLiteral("All files (*)"));
    if (filePath.isEmpty()) {
        return;
    }
    if (m_sendFileField) {
        m_sendFileField->setText(filePath);
    }
}

void BrowserWindow::sendFileFromPanel()
{
    if (!m_sendFileField || !m_sendTargetField) {
        return;
    }
    const QString filePath = m_sendFileField->text().trimmed();
    const QString target = m_sendTargetField->text().trimmed();
    if (filePath.isEmpty()) {
        appendLog("send file skipped: no file selected");
        return;
    }
    if (target.isEmpty()) {
        appendLog("send file skipped: no receiver specified");
        return;
    }
    appendLog(QString("sending file %1 to %2…").arg(filePath, target));
    const QString result = m_backend->sendFile(filePath, target);
    appendLog(result.trimmed());
}

void BrowserWindow::toggleReceiveFromPanel()
{
    if (!m_toggleReceiveBtn) {
        return;
    }
    const bool enabled = m_backend->receiveEnabled();
    const QString result = m_backend->toggleReceive(!enabled);
    appendLog(result.trimmed());
    refreshControlPanel();
}

void BrowserWindow::showFileTransferPage()
{
    navigateTo("vx6://files", false);
}

// backend callbacks
void BrowserWindow::registerBrowserCallbacks()
{
    connect(m_backend, &VX6Backend::logLine, this, &BrowserWindow::appendLog);
}

// first run permission prompt
void BrowserWindow::maybeShowPermissionPrompt()
{
    QSettings settings;
    if (settings.value("browser/permissions_acknowledged", false).toBool())
        return;
    if (!m_backend->needsPermissionPrompt())
    {
        settings.setValue("browser/permissions_acknowledged", true);
        return;
    }

    const auto result = QMessageBox::warning(
        this,
        "VX6 — First-run setup",
        "VX6 needs first-run firewall / admin guidance so the node backend\n"
        "can publish and connect properly.\n\n"
        "Open the permissions page now?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes);

    if (result == QMessageBox::Yes)
    {
        settings.setValue("browser/permissions_acknowledged", true);
        navigateTo("vx6://permissions", false);
    }
}

// tab helpers
QWebEngineView *BrowserWindow::createTab(const QUrl &initialUrl)
{
    auto *view = new QWebEngineView(this);
    auto *page = new QWebEnginePage(m_profile, view);
    view->setPage(page);
    view->settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    view->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);

    connect(view, &QWebEngineView::urlChanged, this, [this, view](const QUrl &url)
            {
        if (view == currentView())
            m_address->setText(url.toString()); });
    connect(view, &QWebEngineView::titleChanged, this, [this, view](const QString &title)
            {
        const int idx = m_tabs->indexOf(view);
        if (idx >= 0)
            m_tabs->setTabText(idx, title.isEmpty() ? "VX6" : title); });
    connect(view, &QWebEngineView::loadFinished, this, [this, view](bool ok)
            { appendLog(QString("[%1] %2").arg(ok ? "ok" : "err", view->url().toString())); });

    view->setUrl(initialUrl);
    return view;
}

QWebEngineView *BrowserWindow::currentView() const
{
    return qobject_cast<QWebEngineView *>(m_tabs->currentWidget());
}

// navigation
void BrowserWindow::openHome()
{
    if (m_tabs->count() == 0)
        newTab();
    navigateTo("vx6://home", false);
}

void BrowserWindow::newTab()
{
    auto *view = createTab(QUrl("vx6://home"));
    const int idx = m_tabs->addTab(view, "VX6");
    m_tabs->setCurrentIndex(idx);
}

void BrowserWindow::closeTab(int index)
{
    if (m_tabs->count() <= 1)
        return;
    QWidget *tab = m_tabs->widget(index);
    m_tabs->removeTab(index);
    tab->deleteLater();
}

void BrowserWindow::currentTabChanged(int index)
{
    if (index < 0)
        return;
    if (auto *view = currentView())
        m_address->setText(view->url().toString());
}

void BrowserWindow::toggleLogs()
{
    m_logDock->setVisible(!m_logDock->isVisible());
}

// node operations
void BrowserWindow::reloadNode()
{
    appendLog("reloading vx6 runtime…");
    appendLog(m_backend->runVX6(QStringList{"reload"}).trimmed());
    if (auto *v = currentView())
        v->reload();
}

void BrowserWindow::startNode()
{
    appendLog(m_backend->startNode());
    refreshStatus();
}

void BrowserWindow::stopNode()
{
    appendLog(m_backend->stopNode());
    refreshStatus();
}

void BrowserWindow::refreshStatus()
{
    appendLog("refreshing status…");
    appendLog(m_backend->runVX6(QStringList{"status"}).trimmed());
    if (currentView())
        currentView()->setUrl(QUrl("vx6://status"));
}

// bookmarks
void BrowserWindow::bookmarkCurrent()
{
    if (auto *view = currentView())
    {
        const QString url = view->url().toString();
        if (!url.isEmpty())
        {
            QSettings settings;
            QStringList bookmarks = settings.value("browser/bookmarks").toStringList();
            if (!bookmarks.contains(url))
            {
                bookmarks.append(url);
                settings.setValue("browser/bookmarks", bookmarks);
                appendLog(QString("bookmarked  %1").arg(url));
            }
        }
    }
}

// url normalization
QString BrowserWindow::normalizeTarget(const QString &raw) const
{
    QString target = raw.trimmed();
    if (target.isEmpty())
        return QStringLiteral("vx6://home");

    if (target.startsWith("vx6://", Qt::CaseInsensitive) ||
        target.startsWith("http://", Qt::CaseInsensitive) ||
        target.startsWith("https://", Qt::CaseInsensitive))
        return target;

    const QString lower = target.toLower();
    if (lower == "status" || lower == "dht" || lower == "registry" ||
        lower == "services" || lower == "peers" || lower == "identity" ||
        lower == "permissions" || lower.startsWith("service/") ||
        lower.startsWith("node/") || lower.startsWith("node-id/") ||
        lower.startsWith("key/"))
        return QStringLiteral("vx6://%1").arg(target);

    if (target.startsWith("localhost", Qt::CaseInsensitive) ||
        target.startsWith("127.") || target.startsWith("[::1]") ||
        target.contains(':'))
        return QStringLiteral("http://%1").arg(target);

    if (target.contains('.') && !target.contains(' '))
        return QStringLiteral("https://%1").arg(target);

    return QStringLiteral("vx6://service/%1").arg(target);
}

void BrowserWindow::navigateTo(const QString &text, bool newTabFlag)
{
    const QUrl url(normalizeTarget(text));
    if (newTabFlag || !currentView())
    {
        auto *view = createTab(url);
        const int idx = m_tabs->addTab(view, url.scheme() == "vx6" ? "VX6" : url.host());
        m_tabs->setCurrentIndex(idx);
    }
    else
    {
        currentView()->setUrl(url);
    }
    m_address->setText(url.toString());
    appendLog(QString("→ %1").arg(url.toString()));
}

void BrowserWindow::openAddress()
{
    navigateTo(m_address->text(), false);
}

// log output
void BrowserWindow::appendLog(const QString &line)
{
    if (!m_logView)
        return;
    m_logView->append(line.trimmed());
}

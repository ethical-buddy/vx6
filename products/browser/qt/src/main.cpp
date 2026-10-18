#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QCommandLineOption>
#include <QWebEngineUrlScheme>

#include "browserwindow.h"

static void registerVX6Scheme()
{
    QWebEngineUrlScheme scheme("vx6");
    scheme.setSyntax(QWebEngineUrlScheme::Syntax::Host);
    scheme.setFlags(QWebEngineUrlScheme::SecureScheme);
    QWebEngineUrlScheme::registerScheme(scheme);
}

int main(int argc, char **argv)
{
    registerVX6Scheme();

    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("vx6");
    QCoreApplication::setOrganizationDomain("vx6.local");
    QCoreApplication::setApplicationName("vx6-browser");

    QCommandLineParser parser;
    parser.setApplicationDescription("VX6 Qt browser shell");
    parser.addHelpOption();
    parser.addOption(QCommandLineOption(QStringList{"b", "vx6-bin"}, "Path to the vx6 binary.", "path"));
    parser.addOption(QCommandLineOption(QStringList{"c", "config"}, "Path to the VX6 config file.", "path"));
    parser.process(app);

    BrowserWindow window(parser.value("vx6-bin"), parser.value("config"));
    window.show();
    return app.exec();
}

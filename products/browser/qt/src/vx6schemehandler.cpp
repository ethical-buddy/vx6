#include "vx6schemehandler.h"

#include "vx6backend.h"

#include <QBuffer>
#include <QWebEngineUrlRequestJob>
#include <QUrl>

VX6SchemeHandler::VX6SchemeHandler(VX6Backend *backend, QObject *parent)
    : QWebEngineUrlSchemeHandler(parent), m_backend(backend)
{
}

void VX6SchemeHandler::requestStarted(QWebEngineUrlRequestJob *job)
{
    const QUrl url = job->requestUrl();
    QString target = url.host().trimmed();
    QString path = url.path().trimmed();
    if (path.startsWith('/'))
    {
        path.remove(0, 1);
    }
    if (!target.isEmpty() && !path.isEmpty())
    {
        target = QString("%1/%2").arg(target, path);
    }
    else if (target.isEmpty())
    {
        target = path;
    }
    if (target.startsWith('/'))
    {
        target.remove(0, 1);
    }

    QString html;
    if (target.isEmpty() || target == "home")
    {
        html = m_backend->homePageHtml();
    }
    else if (target == "status")
    {
        html = m_backend->statusPageHtml();
    }
    else if (target == "dht")
    {
        html = m_backend->dhtPageHtml();
    }
    else if (target == "registry")
    {
        html = m_backend->registryPageHtml();
    }
    else if (target == "services")
    {
        html = m_backend->servicesPageHtml();
    }
    else if (target == "peers")
    {
        html = m_backend->peersPageHtml();
    }
    else if (target == "identity")
    {
        html = m_backend->identityPageHtml();
    }
    else if (target == "files")
    {
        html = m_backend->filesPageHtml();
    }
    else if (target == "transfers"){

    html = m_backend->transfersPageHtml();
    }
    else if (target == "permissions")
    {
        html = m_backend->permissionPromptHtml();
    }
    else if (target.startsWith("service/"))
    {
        html = m_backend->lookupPageHtml("Service Lookup", {"debug", "dht-get", "--service", target.mid(QString("service/").size())}, "Service record and resolution data");
    }
    else if (target.startsWith("node/"))
    {
        html = m_backend->lookupPageHtml("Node Lookup", {"debug", "dht-get", "--node", target.mid(QString("node/").size())}, "Node record and resolution data");
    }
    else if (target.startsWith("node-id/"))
    {
        html = m_backend->lookupPageHtml("Node-ID Lookup", {"debug", "dht-get", "--node-id", target.mid(QString("node-id/").size())}, "Node-ID lookup data");
    }
    else if (target.startsWith("key/"))
    {
        html = m_backend->lookupPageHtml("Raw Key Lookup", {"debug", "dht-get", "--key", target.mid(QString("key/").size())}, "Raw key lookup data");
    }
    else
    {
        html = m_backend->lookupPageHtml("VX6 Target", {"debug", "dht-get", "--key", target}, "Unknown VX6 target; showing raw lookup output.");
    }

    auto *buffer = new QBuffer(job);
    buffer->setData(html.toUtf8());
    buffer->open(QIODevice::ReadOnly);
    job->reply("text/html; charset=utf-8", buffer);
}

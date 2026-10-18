#pragma once

#include <QWebEngineUrlSchemeHandler>

class VX6Backend;

class VX6SchemeHandler : public QWebEngineUrlSchemeHandler
{
    Q_OBJECT

public:
    explicit VX6SchemeHandler(VX6Backend *backend, QObject *parent = nullptr);
    void requestStarted(QWebEngineUrlRequestJob *job) override;

private:
    VX6Backend *m_backend;
};


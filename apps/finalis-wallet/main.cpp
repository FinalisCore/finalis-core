// SPDX-License-Identifier: MIT

#include <QApplication>
#include <QIcon>
#include <QPalette>
#include <QStyleFactory>

#include "wallet_window.hpp"

int main(int argc, char* argv[]) {
  QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
  QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
  QApplication app(argc, argv);
  QApplication::setOrganizationName("finalis");
  QApplication::setApplicationName("finalis-wallet");
  if (auto* style = QStyleFactory::create("Fusion")) app.setStyle(style);
  app.setWindowIcon(QIcon(":/branding/finalis-app-icon.svg"));

  finalis::wallet::WalletWindow window;
  window.show();
  return app.exec();
}

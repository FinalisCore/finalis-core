// SPDX-License-Identifier: MIT

#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

namespace finalis::wallet {

class OverviewPage final : public QWidget {
 public:
  explicit OverviewPage(QWidget* parent = nullptr);

  QLabel* wallet_status_label() const { return wallet_status_label_; }
  QLabel* wallet_file_label() const { return wallet_file_label_; }
  QLabel* network_label() const { return network_label_; }
  QLabel* balance_label() const { return balance_label_; }
  QLabel* pending_balance_label() const { return pending_balance_label_; }
  QLabel* confidential_balance_label() const { return confidential_balance_label_; }
  QLabel* receive_address_label() const { return receive_address_label_; }
  QLabel* confidential_receive_label() const { return confidential_receive_label_; }
  QLabel* tip_status_label() const { return tip_status_label_; }
  QLabel* connection_status_label() const { return connection_status_label_; }
  QPushButton* send_button() const { return send_button_; }
  QPushButton* receive_button() const { return receive_button_; }
  QPushButton* view_activity_button() const { return view_activity_button_; }
  QPushButton* open_explorer_button() const { return open_explorer_button_; }
  QTableWidget* activity_preview_table() const { return activity_preview_table_; }

 private:
  QLabel* wallet_status_label_{nullptr};
  QLabel* wallet_file_label_{nullptr};
  QLabel* network_label_{nullptr};
  QLabel* balance_label_{nullptr};
  QLabel* pending_balance_label_{nullptr};
  QLabel* confidential_balance_label_{nullptr};
  QLabel* receive_address_label_{nullptr};
  QLabel* confidential_receive_label_{nullptr};
  QLabel* tip_status_label_{nullptr};
  QLabel* connection_status_label_{nullptr};
  QPushButton* send_button_{nullptr};
  QPushButton* receive_button_{nullptr};
  QPushButton* view_activity_button_{nullptr};
  QPushButton* open_explorer_button_{nullptr};
  QTableWidget* activity_preview_table_{nullptr};
};

}  // namespace finalis::wallet

// SPDX-License-Identifier: MIT

#pragma once

#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;

namespace finalis::wallet {

class ActivityPage final : public QWidget {
 public:
  explicit ActivityPage(QWidget* parent = nullptr);

  QComboBox* filter_combo() const { return filter_combo_; }
  QPushButton* detail_button() const { return detail_button_; }
  QTableWidget* table() const { return table_; }
  QLabel* finalized_count_label() const { return finalized_count_label_; }
  QLabel* pending_count_label() const { return pending_count_label_; }
  QLabel* local_count_label() const { return local_count_label_; }
  QLabel* mint_count_label() const { return mint_count_label_; }
  QLabel* confidential_count_label() const { return confidential_count_label_; }
  QLabel* detail_title_label() const { return detail_title_label_; }
  QTextEdit* detail_view() const { return detail_view_; }

 private:
  QComboBox* filter_combo_{nullptr};
  QPushButton* detail_button_{nullptr};
  QTableWidget* table_{nullptr};
  QLabel* finalized_count_label_{nullptr};
  QLabel* pending_count_label_{nullptr};
  QLabel* local_count_label_{nullptr};
  QLabel* mint_count_label_{nullptr};
  QLabel* confidential_count_label_{nullptr};
  QLabel* detail_title_label_{nullptr};
  QTextEdit* detail_view_{nullptr};
};

}  // namespace finalis::wallet

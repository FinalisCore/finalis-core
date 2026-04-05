#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QTextEdit;

namespace finalis::wallet {

class ReceivePage final : public QWidget {
 public:
  explicit ReceivePage(QWidget* parent = nullptr);

  QLabel* address_label() const { return address_label_; }
  QPushButton* copy_button() const { return copy_button_; }
  QLabel* copy_status_label() const { return copy_status_label_; }
  QLabel* heading_label() const { return heading_label_; }
  QLabel* finalized_note_label() const { return finalized_note_label_; }

 private:
  QLabel* heading_label_{nullptr};
  QLabel* address_label_{nullptr};
  QPushButton* copy_button_{nullptr};
  QLabel* copy_status_label_{nullptr};
  QLabel* finalized_note_label_{nullptr};
};

}  // namespace finalis::wallet

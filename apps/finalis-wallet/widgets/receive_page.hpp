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
  QLabel* confidential_address_label() const { return confidential_address_label_; }
  QLabel* confidential_request_label() const { return confidential_request_label_; }
  QPushButton* copy_button() const { return copy_button_; }
  QPushButton* generate_confidential_request_button() const { return generate_confidential_request_button_; }
  QPushButton* copy_confidential_request_button() const { return copy_confidential_request_button_; }
  QLabel* copy_status_label() const { return copy_status_label_; }
  QLabel* heading_label() const { return heading_label_; }
  QLabel* finalized_note_label() const { return finalized_note_label_; }
  QLabel* confidential_note_label() const { return confidential_note_label_; }

 private:
  QLabel* heading_label_{nullptr};
  QLabel* address_label_{nullptr};
  QLabel* confidential_address_label_{nullptr};
  QLabel* confidential_request_label_{nullptr};
  QPushButton* copy_button_{nullptr};
  QPushButton* generate_confidential_request_button_{nullptr};
  QPushButton* copy_confidential_request_button_{nullptr};
  QLabel* copy_status_label_{nullptr};
  QLabel* finalized_note_label_{nullptr};
  QLabel* confidential_note_label_{nullptr};
};

}  // namespace finalis::wallet

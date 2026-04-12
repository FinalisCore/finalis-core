#pragma once

#include <QWidget>

class QLineEdit;
class QPushButton;
class QLabel;
class QComboBox;

namespace finalis::wallet {

class SendPage final : public QWidget {
 public:
  explicit SendPage(QWidget* parent = nullptr);

  QLineEdit* address_edit() const { return address_edit_; }
  QComboBox* mode_combo() const { return mode_combo_; }
  QLineEdit* amount_edit() const { return amount_edit_; }
  QLineEdit* fee_edit() const { return fee_edit_; }
  QPushButton* max_button() const { return max_button_; }
  QPushButton* import_confidential_request_button() const { return import_confidential_request_button_; }
  QPushButton* review_button() const { return review_button_; }
  QPushButton* send_button() const { return send_button_; }
  QLabel* review_status_label() const { return review_status_label_; }
  QLabel* review_warning_label() const { return review_warning_label_; }
  QLabel* review_recipient_label() const { return review_recipient_label_; }
  QLabel* review_amount_label() const { return review_amount_label_; }
  QLabel* review_fee_label() const { return review_fee_label_; }
  QLabel* review_total_label() const { return review_total_label_; }
  QLabel* review_change_label() const { return review_change_label_; }
  QLabel* review_inputs_label() const { return review_inputs_label_; }
  QLabel* review_note_label() const { return review_note_label_; }

 private:
  QLineEdit* address_edit_{nullptr};
  QComboBox* mode_combo_{nullptr};
  QLineEdit* amount_edit_{nullptr};
  QLineEdit* fee_edit_{nullptr};
  QPushButton* max_button_{nullptr};
  QPushButton* import_confidential_request_button_{nullptr};
  QPushButton* review_button_{nullptr};
  QPushButton* send_button_{nullptr};
  QLabel* review_status_label_{nullptr};
  QLabel* review_warning_label_{nullptr};
  QLabel* review_recipient_label_{nullptr};
  QLabel* review_amount_label_{nullptr};
  QLabel* review_fee_label_{nullptr};
  QLabel* review_total_label_{nullptr};
  QLabel* review_change_label_{nullptr};
  QLabel* review_inputs_label_{nullptr};
  QLabel* review_note_label_{nullptr};
};

}  // namespace finalis::wallet

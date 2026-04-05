#pragma once

#include <QWidget>

class QCheckBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QScrollArea;
class QTableWidget;
class QTabWidget;
class QTextEdit;
class QWidget;

namespace finalis::wallet {

class AdvancedPage final : public QWidget {
 public:
  explicit AdvancedPage(QWidget* parent = nullptr);

  QLabel* validator_readiness_label() const { return validator_readiness_label_; }
  QLabel* validator_funding_label() const { return validator_funding_label_; }
  QLabel* validator_state_label() const { return validator_state_label_; }
  QPushButton* validator_action_button() const { return validator_action_button_; }
  QLineEdit* validator_db_path_edit() const { return validator_db_path_edit_; }
  QLineEdit* validator_key_path_edit() const { return validator_key_path_edit_; }
  QLineEdit* validator_rpc_url_edit() const { return validator_rpc_url_edit_; }
  QPushButton* validator_db_browse_button() const { return validator_db_browse_button_; }
  QPushButton* validator_key_browse_button() const { return validator_key_browse_button_; }
  QPushButton* validator_refresh_button() const { return validator_refresh_button_; }
  QPushButton* validator_cancel_button() const { return validator_cancel_button_; }
  QPushButton* validator_toggle_details_button() const { return validator_toggle_details_button_; }
  QTextEdit* validator_details_view() const { return validator_details_view_; }
  QLabel* validator_summary_label() const { return validator_summary_label_; }
  QWidget* validator_details_container() const { return validator_details_container_; }

  QLineEdit* mint_deposit_amount_edit() const { return mint_deposit_amount_edit_; }
  QLineEdit* mint_redeem_amount_edit() const { return mint_redeem_amount_edit_; }
  QLineEdit* mint_redeem_address_edit() const { return mint_redeem_address_edit_; }
  QLineEdit* mint_issue_amount_edit() const { return mint_issue_amount_edit_; }
  QLabel* mint_deposit_ref_label() const { return mint_deposit_ref_label_; }
  QLabel* mint_notes_label() const { return mint_notes_label_; }
  QLabel* mint_redemption_label() const { return mint_redemption_label_; }
  QLabel* mint_status_label() const { return mint_status_label_; }
  QLabel* mint_private_balance_label() const { return mint_private_balance_label_; }
  QLabel* mint_note_count_label() const { return mint_note_count_label_; }
  QTableWidget* mint_deposits_view() const { return mint_deposits_view_; }
  QTableWidget* mint_notes_view() const { return mint_notes_view_; }
  QTableWidget* mint_redemptions_view() const { return mint_redemptions_view_; }
  QPushButton* mint_detail_button() const { return mint_detail_button_; }
  QPushButton* mint_deposit_button() const { return mint_deposit_button_; }
  QPushButton* mint_issue_button() const { return mint_issue_button_; }
  QPushButton* mint_redeem_button() const { return mint_redeem_button_; }
  QPushButton* mint_redeem_status_button() const { return mint_redeem_status_button_; }

  QTextEdit* lightserver_urls_edit() const { return lightserver_urls_edit_; }
  QCheckBox* pin_lightserver_endpoint_checkbox() const { return pin_lightserver_endpoint_checkbox_; }
  QLineEdit* mint_url_edit() const { return mint_url_edit_; }
  QLineEdit* mint_id_edit() const { return mint_id_edit_; }
  QLabel* connection_summary_label() const { return connection_summary_label_; }
  QPushButton* save_settings_button() const { return save_settings_button_; }

  QTextEdit* crosscheck_detail_view() const { return crosscheck_detail_view_; }
  QTextEdit* adaptive_regime_view() const { return adaptive_regime_view_; }
  QTabWidget* tab_widget() const { return tabs_; }

 private:
  QTabWidget* tabs_{nullptr};

  QLabel* validator_readiness_label_{nullptr};
  QLabel* validator_funding_label_{nullptr};
  QLabel* validator_state_label_{nullptr};
  QLabel* validator_summary_label_{nullptr};
  QPushButton* validator_action_button_{nullptr};
  QPushButton* validator_refresh_button_{nullptr};
  QPushButton* validator_cancel_button_{nullptr};
  QPushButton* validator_toggle_details_button_{nullptr};
  QLineEdit* validator_db_path_edit_{nullptr};
  QLineEdit* validator_key_path_edit_{nullptr};
  QLineEdit* validator_rpc_url_edit_{nullptr};
  QPushButton* validator_db_browse_button_{nullptr};
  QPushButton* validator_key_browse_button_{nullptr};
  QWidget* validator_details_container_{nullptr};
  QTextEdit* validator_details_view_{nullptr};

  QLineEdit* mint_deposit_amount_edit_{nullptr};
  QLineEdit* mint_redeem_amount_edit_{nullptr};
  QLineEdit* mint_redeem_address_edit_{nullptr};
  QLineEdit* mint_issue_amount_edit_{nullptr};
  QLabel* mint_deposit_ref_label_{nullptr};
  QLabel* mint_notes_label_{nullptr};
  QLabel* mint_redemption_label_{nullptr};
  QLabel* mint_status_label_{nullptr};
  QLabel* mint_private_balance_label_{nullptr};
  QLabel* mint_note_count_label_{nullptr};
  QTableWidget* mint_deposits_view_{nullptr};
  QTableWidget* mint_notes_view_{nullptr};
  QTableWidget* mint_redemptions_view_{nullptr};
  QPushButton* mint_detail_button_{nullptr};
  QPushButton* mint_deposit_button_{nullptr};
  QPushButton* mint_issue_button_{nullptr};
  QPushButton* mint_redeem_button_{nullptr};
  QPushButton* mint_redeem_status_button_{nullptr};

  QTextEdit* lightserver_urls_edit_{nullptr};
  QCheckBox* pin_lightserver_endpoint_checkbox_{nullptr};
  QLineEdit* mint_url_edit_{nullptr};
  QLineEdit* mint_id_edit_{nullptr};
  QLabel* connection_summary_label_{nullptr};
  QPushButton* save_settings_button_{nullptr};

  QTextEdit* crosscheck_detail_view_{nullptr};
  QTextEdit* adaptive_regime_view_{nullptr};
};

}  // namespace finalis::wallet

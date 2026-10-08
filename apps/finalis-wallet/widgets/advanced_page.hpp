// SPDX-License-Identifier: MIT

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
  QLabel* validator_required_bond_label() const { return validator_required_bond_label_; }
  QLabel* validator_available_balance_label() const { return validator_available_balance_label_; }
  QLabel* validator_blockers_label() const { return validator_blockers_label_; }
  QLabel* validator_live_status_label() const { return validator_live_status_label_; }
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


  QTextEdit* lightserver_urls_edit() const { return lightserver_urls_edit_; }
  QCheckBox* pin_lightserver_endpoint_checkbox() const { return pin_lightserver_endpoint_checkbox_; }
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
  QLabel* validator_required_bond_label_{nullptr};
  QLabel* validator_available_balance_label_{nullptr};
  QLabel* validator_blockers_label_{nullptr};
  QLabel* validator_live_status_label_{nullptr};
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


  QTextEdit* lightserver_urls_edit_{nullptr};
  QCheckBox* pin_lightserver_endpoint_checkbox_{nullptr};
  QLabel* connection_summary_label_{nullptr};
  QPushButton* save_settings_button_{nullptr};

  QTextEdit* crosscheck_detail_view_{nullptr};
  QTextEdit* adaptive_regime_view_{nullptr};
};

}  // namespace finalis::wallet

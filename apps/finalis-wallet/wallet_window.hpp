#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QUrl>

#include "common/types.hpp"
#include "lightserver/client.hpp"
#include "onboarding/validator_onboarding.hpp"
#include "utxo/tx.hpp"
#include "wallet_store.hpp"

class QLabel;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QPushButton;
class QScrollArea;
class QTableWidget;
class QTabWidget;
class QFrame;
class QTextEdit;
class QTimer;

namespace finalis::keystore {
struct ValidatorKey;
}

namespace finalis::wallet {

QString onboarding_error_display_text(const QString& error_code, const QString& fallback_message);
QString onboarding_badge_html(const QString& badge);

struct HistoryFlowClassification {
  QString kind;
  QString detail;
};

HistoryFlowClassification classify_wallet_history_flow(std::uint64_t credited, std::uint64_t debited);

class ActivityPage;
class AdvancedPage;
class OverviewPage;
class ReceivePage;
class SendPage;
class SettingsPage;

class WalletWindow final : public QMainWindow {
 public:
  struct MintNote {
    QString note_ref;
    std::uint64_t amount{0};
  };

  struct ChainRecord {
    QString status;
    QString kind;
    QString amount;
    QString reference;
    QString height;
    QString txid;
    QString details;
  };

  WalletWindow();

 private:
  struct LoadedWallet {
    std::string file_path;
    std::string passphrase;
    std::string network_name;
    std::string address;
    std::string pubkey_hex;
  };

  struct WalletUtxo {
    std::string txid_hex;
    std::uint32_t vout{0};
    std::uint64_t value{0};
    std::uint64_t height{0};
    finalis::Bytes script_pubkey;
  };

  struct MintRecord {
    QString status;
    QString kind;
    QString reference;
    QString amount;
    QString height_or_state;
    QString details;
  };

  struct HistoryRowRef {
    enum class Source { Chain, Mint, Local, Confidential };
    Source source{Source::Chain};
    int index{-1};
  };

  struct ConfidentialRequestView {
    QString request_id;
    QString account_id;
    QString one_time_pubkey_hex;
    QString ephemeral_pubkey_hex;
    std::uint8_t scan_tag{0};
    bool consumed{false};
  };

  struct ConfidentialCoinView {
    OutPoint outpoint{};
    QString txid_hex;
    std::uint32_t vout{0};
    QString account_id;
    std::uint64_t amount{0};
    QString one_time_pubkey_hex;
    bool spent{false};
  };

  struct EndpointRuntimeState {
    QString last_success;
    QString last_failure;
    QString last_error;
  };

  struct CachedPendingTxStatus {
    lightserver::TxStatusView status;
    QString endpoint;
    QString cached_at;
    std::uint64_t cached_at_ms{0};
  };

  struct EndpointObservation {
    QString endpoint;
    QString network_name;
    QString network_id;
    QString genesis_hash;
    std::uint64_t tip_height{0};
    QString transition_hash;
    QString binary_version;
    QString wallet_api_version;
    bool chain_id_ok{true};
    bool bootstrap_sync_incomplete{false};
    bool peer_height_disagreement{false};
    QString error;
  };

  enum class HistoryPersistMode : std::uint8_t { None = 0, Replace = 1, Append = 2 };

  struct RefreshRequest {
    QString wallet_address;
    QString wallet_network_name;
    QStringList endpoints;
    std::uint64_t previous_tip_height{0};
    QString previous_transition_hash;
    std::vector<ChainRecord> current_chain_records;
    std::vector<std::string> local_sent_txids;
    std::map<std::string, std::vector<OutPoint>> pending_wallet_spends;
    std::vector<WalletStore::PendingSpend> pending_spend_records;
    std::optional<std::uint64_t> finalized_history_cursor_height;
    std::optional<std::string> finalized_history_cursor_txid;
    std::map<std::string, std::pair<QString, QString>> finalized_tx_summary_cache;
  };

  struct EndpointProbeResult {
    QString endpoint;
    bool healthy{false};
    QString error;
    std::optional<lightserver::RpcStatusView> status;
    std::optional<lightserver::AddressValidationView> validated_address;
    std::optional<std::vector<lightserver::UtxoView>> utxos;
  };

  struct RefreshResult {
    bool success{false};
    QString error;
    QString active_endpoint;
    std::optional<lightserver::RpcStatusView> status;
    std::vector<WalletUtxo> utxos;
    std::vector<ChainRecord> chain_records;
    std::vector<std::string> local_sent_txids;
    std::map<std::string, std::vector<OutPoint>> pending_wallet_spends;
    std::optional<std::uint64_t> finalized_history_cursor_height;
    std::optional<std::string> finalized_history_cursor_txid;
    std::map<std::string, std::pair<QString, QString>> finalized_tx_summary_cache;
    std::vector<EndpointObservation> observations;
    std::vector<std::pair<QString, QString>> endpoint_failures;
    std::optional<std::pair<QString, bool>> endpoint_success;
    HistoryPersistMode history_persist_mode{HistoryPersistMode::None};
    std::vector<WalletStore::FinalizedHistoryRecord> history_records;
    bool update_history_cursor{false};
    std::vector<std::string> remove_pending_txids;
    std::vector<std::string> remove_sent_txids;
    std::vector<OutPoint> mark_spent_confidential_outpoints;
    std::vector<std::string> released_pending_txids;
    std::vector<EndpointProbeResult> probe_results;
  };

  void build_ui();
  void load_settings();
  void save_settings() const;
  void apply_selected_theme();
  void update_wallet_views();
  void update_connection_views();
  void update_adaptive_regime_view();
  bool refresh_finalized_send_state(QString* err = nullptr);
  void refresh_chain_state(bool interactive);
  void update_validator_onboarding_view();
  void refresh_validator_readiness_panel(bool interactive = false);
  void start_validator_onboarding_clicked();
  void start_onboarding_registration_clicked();
  void cancel_validator_onboarding_clicked();
  void browse_validator_db_path();
  void browse_validator_key_path();
  void toggle_validator_details();
  void persist_validator_onboarding_ui_state(const std::optional<finalis::onboarding::ValidatorOnboardingRecord>& record,
                                             const QString& last_error = {}) const;
  QStringList configured_lightserver_endpoints() const;
  QStringList ordered_lightserver_endpoints() const;
  void set_lightserver_endpoints(const QStringList& endpoints);
  void record_lightserver_success(const QString& endpoint, bool fallback_used);
  void record_lightserver_failure(const QString& endpoint, const QString& error);
  void clear_lightserver_runtime_status();
  void update_crosscheck_summary(const std::vector<EndpointObservation>& observations);
  std::optional<lightserver::BroadcastResult> broadcast_tx_with_failover(const Bytes& tx_bytes, std::string* err,
                                                                         QString* used_endpoint = nullptr);
  void render_history_view();
  void render_confidential_receive_views();
  void update_selected_confidential_pending_tx_status_panel();
  void persist_wallet_view_snapshot();
  void request_pending_tx_status_refresh(const QString& txid);
  void refresh_overview_activity_preview();
  void update_selected_history_detail();
  void render_mint_state();
  void reset_send_review_panel();
  void show_send_inline_warning(const QString& text);
  void show_send_inline_status(const QString& text);
  void save_wallet_local_state();
  void load_wallet_local_state();
  bool open_wallet_store();
  void append_local_event(const QString& line);

  void create_wallet();
  void open_wallet();
  void import_wallet();
  void unlock_confidential_state();
  void create_confidential_account();
  void import_confidential_account();
  void generate_confidential_request();
  void import_received_confidential_tx();
  void import_confidential_request();
  void export_wallet_secret();
  void show_about();
  void save_connection_settings();
  void validate_send_form();
  void populate_send_max_amount();
  void submit_send();
  void show_selected_history_detail();
  void show_selected_mint_detail();
  void submit_mint_deposit();
  void issue_mint_note();
  void submit_mint_redemption();
  void refresh_mint_redemption_status();
  void refresh_history_table();
  QUrl explorer_home_url() const;
  void open_explorer_home();
  void poll_finalized_tip_status();
  static RefreshResult build_refresh_result(const RefreshRequest& request);
  void apply_refresh_result(std::uint64_t generation, std::uint64_t base_state_version, bool interactive, RefreshResult result);
  void mark_refresh_state_changed();

  std::optional<LoadedWallet> load_wallet_file(const QString& path, const QString& passphrase);
  std::optional<QString> prompt_passphrase(const QString& title, bool confirm) const;
  bool ensure_wallet_loaded(const QString& action_name);
  std::optional<finalis::keystore::ValidatorKey> load_wallet_key(std::string* err) const;
  std::optional<std::string> inferred_local_db_path() const;
  std::optional<std::vector<std::pair<OutPoint, TxOut>>> send_available_prevs(std::size_t* reserved_excluded,
                                                                              std::size_t* pending_reserved_excluded,
                                                                              std::size_t* onboarding_reserved_excluded,
                                                                              QString* err);
  std::set<OutPoint> pending_wallet_reserved_outpoints() const;

  QTabWidget* tabs_{nullptr};
  OverviewPage* overview_page_{nullptr};
  SendPage* send_page_{nullptr};
  ReceivePage* receive_page_{nullptr};
  ActivityPage* activity_page_{nullptr};
  AdvancedPage* advanced_page_{nullptr};
  SettingsPage* settings_page_{nullptr};

  QLabel* wallet_status_label_{nullptr};
  QLabel* wallet_file_label_{nullptr};
  QLabel* network_label_{nullptr};
  QLabel* overview_connection_status_label_{nullptr};
  QLabel* header_logo_label_{nullptr};
  QLabel* header_title_label_{nullptr};
  QLabel* header_network_label_{nullptr};
  QLabel* header_tip_label_{nullptr};
  QLabel* header_connection_label_{nullptr};
  QLabel* header_crosscheck_label_{nullptr};
  QLabel* balance_label_{nullptr};
  QLabel* pending_balance_label_{nullptr};
  QLabel* confidential_balance_label_{nullptr};
  QLabel* receive_address_home_label_{nullptr};
  QLabel* receive_address_label_{nullptr};
  QLabel* overview_confidential_receive_label_{nullptr};
  QLabel* receive_copy_status_label_{nullptr};
  QLabel* receive_finalized_note_label_{nullptr};
  QLabel* receive_confidential_address_label_{nullptr};
  QLabel* receive_confidential_request_label_{nullptr};
  QLabel* receive_confidential_request_summary_label_{nullptr};
  QTableWidget* receive_confidential_requests_table_{nullptr};
  QLabel* receive_confidential_coin_summary_label_{nullptr};
  QTableWidget* receive_confidential_coins_table_{nullptr};
  QTextEdit* receive_confidential_pending_status_view_{nullptr};
  QPushButton* receive_copy_confidential_pending_txid_button_{nullptr};
  QPushButton* receive_inspect_confidential_pending_tx_button_{nullptr};
  QLabel* receive_confidential_note_label_{nullptr};
  QComboBox* history_filter_combo_{nullptr};
  QTableWidget* history_view_{nullptr};
  QLabel* tip_status_label_{nullptr};
  QLabel* validator_readiness_label_{nullptr};
  QLabel* validator_funding_label_{nullptr};
  QLabel* validator_state_label_{nullptr};
  QLabel* validator_required_bond_label_{nullptr};
  QLabel* validator_available_balance_label_{nullptr};
  QLabel* validator_blockers_label_{nullptr};
  QLabel* validator_live_status_label_{nullptr};
  QLabel* validator_summary_label_{nullptr};
  QPushButton* history_detail_button_{nullptr};
  QPushButton* overview_send_button_{nullptr};
  QPushButton* overview_receive_button_{nullptr};
  QPushButton* overview_activity_button_{nullptr};
  QPushButton* overview_open_explorer_button_{nullptr};
  QPushButton* validator_action_button_{nullptr};
  QPushButton* validator_refresh_button_{nullptr};
  QPushButton* validator_cancel_button_{nullptr};
  QPushButton* validator_toggle_details_button_{nullptr};
  QLineEdit* validator_db_path_edit_{nullptr};
  QLineEdit* validator_key_path_edit_{nullptr};
  QLineEdit* validator_rpc_url_edit_{nullptr};
  QLabel* activity_finalized_count_label_{nullptr};
  QLabel* activity_pending_count_label_{nullptr};
  QLabel* activity_local_count_label_{nullptr};
  QLabel* activity_mint_count_label_{nullptr};
  QLabel* activity_confidential_count_label_{nullptr};
  QLabel* activity_detail_title_label_{nullptr};
  QTextEdit* activity_detail_view_{nullptr};

  QLineEdit* send_address_edit_{nullptr};
  QComboBox* send_mode_combo_{nullptr};
  QLineEdit* send_amount_edit_{nullptr};
  QLineEdit* send_fee_edit_{nullptr};
  QPushButton* send_max_button_{nullptr};
  QPushButton* send_import_confidential_request_button_{nullptr};
  QPushButton* send_review_button_{nullptr};
  QPushButton* send_button_{nullptr};
  QLabel* send_review_status_label_{nullptr};
  QLabel* send_review_warning_label_{nullptr};
  QLabel* send_review_recipient_label_{nullptr};
  QLabel* send_review_amount_label_{nullptr};
  QLabel* send_review_fee_label_{nullptr};
  QLabel* send_review_total_label_{nullptr};
  QLabel* send_review_change_label_{nullptr};
  QLabel* send_review_inputs_label_{nullptr};
  QLabel* send_review_note_label_{nullptr};

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

  QTextEdit* lightserver_urls_edit_{nullptr};
  QCheckBox* pin_lightserver_endpoint_checkbox_{nullptr};
  QLineEdit* mint_url_edit_{nullptr};
  QLineEdit* mint_id_edit_{nullptr};
  QComboBox* theme_combo_{nullptr};
  QLabel* branding_symbol_label_{nullptr};
  QLabel* connection_summary_label_{nullptr};
  QTextEdit* crosscheck_detail_view_{nullptr};
  QTextEdit* adaptive_regime_view_{nullptr};
  QTextEdit* validator_details_view_{nullptr};
  QPushButton* save_settings_button_{nullptr};
  QPushButton* about_button_{nullptr};
  QPushButton* mint_deposit_button_{nullptr};
  QPushButton* mint_issue_button_{nullptr};
  QPushButton* mint_redeem_button_{nullptr};
  QPushButton* mint_redeem_status_button_{nullptr};
  QTimer* finalized_tip_poll_timer_{nullptr};

  std::optional<LoadedWallet> wallet_;
  std::vector<WalletUtxo> utxos_;
  QStringList local_history_lines_;
  std::vector<std::string> local_sent_txids_;
  std::map<std::string, std::vector<OutPoint>> pending_wallet_spends_;
  std::map<OutPoint, WalletStore::PendingSpend> pending_confidential_reservations_;
  std::optional<std::uint64_t> finalized_history_cursor_height_;
  std::optional<std::string> finalized_history_cursor_txid_;
  std::uint64_t tip_height_{0};
  QString mint_deposit_ref_;
  QString mint_last_deposit_txid_;
  std::uint32_t mint_last_deposit_vout_{0};
  QString mint_last_redemption_batch_id_;
  QString confidential_receive_address_;
  std::uint64_t confidential_balance_units_{0};
  std::size_t confidential_coin_count_{0};
  bool confidential_storage_locked_{false};
  std::vector<MintNote> mint_notes_;
  std::vector<ChainRecord> chain_records_;
  std::vector<MintRecord> mint_records_;
  std::vector<ConfidentialRequestView> confidential_request_views_;
  std::vector<ConfidentialCoinView> confidential_coin_views_;
  std::vector<HistoryRowRef> history_row_refs_;
  QString current_chain_name_;
  QString current_transition_hash_;
  QString current_network_id_;
  QString current_genesis_hash_;
  QString current_binary_version_;
  QString current_wallet_api_version_;
  std::optional<lightserver::RpcStatusView> current_lightserver_status_;
  std::optional<qulonglong> current_finalized_lag_;
  bool current_peer_height_disagreement_{false};
  bool current_bootstrap_sync_incomplete_{false};
  QString last_refresh_text_;
  QString last_refresh_endpoint_;
  QString last_polled_transition_hash_;
  std::uint64_t last_polled_tip_height_{0};
  QString last_successful_lightserver_endpoint_;
  QString last_failed_lightserver_endpoint_;
  QString last_lightserver_error_;
  bool last_refresh_used_fallback_{false};
  QString crosscheck_summary_{"Cross-check: unavailable"};
  QString crosscheck_detail_text_{"No endpoint cross-check yet."};
  std::map<QString, EndpointRuntimeState> endpoint_runtime_state_;
  std::map<QString, CachedPendingTxStatus> pending_tx_status_cache_;
  std::optional<WalletStore::WalletViewSnapshot> wallet_view_snapshot_;
  QString pending_tx_status_panel_txid_;
  std::uint64_t pending_tx_status_generation_{0};
  std::map<std::string, std::pair<QString, QString>> finalized_tx_summary_cache_;
  std::uint64_t refresh_generation_{0};
  std::uint64_t refresh_state_version_{0};
  std::uint64_t tip_poll_generation_{0};
  std::uint64_t mint_status_refresh_generation_{0};
  std::uint64_t last_validator_auto_refresh_ms_{0};
  std::uint64_t validator_refresh_generation_{0};
  bool tip_poll_in_flight_{false};
  bool mint_status_refresh_in_flight_{false};
  bool validator_refresh_in_flight_{false};
  bool refresh_in_flight_{false};
  std::vector<EndpointProbeResult> last_endpoint_probe_results_;
  std::chrono::steady_clock::time_point last_probe_time_;
  WalletStore store_;
};

}  // namespace finalis::wallet

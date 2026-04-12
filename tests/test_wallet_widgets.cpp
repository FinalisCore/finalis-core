#include <QApplication>
#include <QByteArray>
#include <QComboBox>
#include <QDateTime>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "apps/finalis-wallet/widgets/activity_page.hpp"
#include "apps/finalis-wallet/widgets/advanced_page.hpp"

#define private public
#include "apps/finalis-wallet/wallet_window.hpp"
#undef private

namespace {

constexpr const char* kSettingsOrg = "finalis";
constexpr const char* kSettingsApp = "finalis-wallet";

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

void test_activity_page_local_filter_and_chips() {
  finalis::wallet::ActivityPage page;
  auto* filter = page.filter_combo();
  require(filter != nullptr, "activity filter combo missing");
  require(filter->count() == 6, "activity filter count mismatch");
  require(filter->itemText(0).toStdString() == "All", "activity filter missing All");
  require(filter->itemText(1).toStdString() == "On-Chain", "activity filter missing On-Chain");
  require(filter->itemText(2).toStdString() == "Local", "activity filter missing Local");
  require(filter->itemText(3).toStdString() == "Mint", "activity filter missing Mint");
  require(filter->itemText(4).toStdString() == "Confidential", "activity filter missing Confidential");
  require(filter->itemText(5).toStdString() == "Pending", "activity filter missing Pending");

  auto* local = page.local_count_label();
  require(local != nullptr, "local chip missing");
  require(local->text().toStdString() == "Local: 0", "local chip default text mismatch");
  require(local->property("role").toString().toStdString() == "chip", "local chip role mismatch");

  auto* detail_title = page.detail_title_label();
  require(detail_title != nullptr, "detail title missing");
  require(detail_title->text().toStdString() == "No record selected", "detail title default mismatch");
}

void test_wallet_window_history_selection_updates_detail_panel() {
  finalis::wallet::WalletWindow window;
  require(window.history_view_ != nullptr, "wallet history table missing");
  require(window.activity_detail_title_label_ != nullptr, "wallet detail title missing");
  require(window.activity_detail_view_ != nullptr, "wallet detail view missing");

  window.chain_records_.clear();
  window.mint_records_.clear();
  window.local_history_lines_.clear();
  window.history_row_refs_.clear();
  window.chain_records_.push_back(finalis::wallet::WalletWindow::ChainRecord{
      "FINALIZED",
      "SENT",
      "12.5 FLS",
      "abcd1234efgh5678",
      "Height 42",
      "txid-42",
      "Local pending send was replaced by finalized chain activity.",
  });
  window.history_row_refs_.push_back(
      finalis::wallet::WalletWindow::HistoryRowRef{finalis::wallet::WalletWindow::HistoryRowRef::Source::Chain, 0});

  auto* table = window.history_view_;
  table->clearContents();
  table->setRowCount(1);
  table->setItem(0, 0, new QTableWidgetItem("Sent"));
  table->setItem(0, 1, new QTableWidgetItem("Finalized"));
  table->setItem(0, 2, new QTableWidgetItem("12.5 FLS"));
  table->setItem(0, 3, new QTableWidgetItem("abcd1234"));
  table->setItem(0, 4, new QTableWidgetItem("Height 42"));
  table->setCurrentItem(table->item(0, 0));
  table->setCurrentCell(0, 0);
  table->selectRow(0);
  QApplication::processEvents();
  require(table->currentRow() == 0, "wallet history row did not become current");
  window.update_selected_history_detail();

  const std::string title = window.activity_detail_title_label_->text().toStdString();
  const std::string detail = window.activity_detail_view_->toPlainText().toStdString();
  require(title.find("Finalized") != std::string::npos,
          std::string("wallet detail title missing finalized state: ") + title + " | detail: " + detail);
  require(title.find("Sent") != std::string::npos,
          std::string("wallet detail title missing chain kind: ") + title + " | detail: " + detail);
  require(detail.find("Reference: abcd1234efgh5678") != std::string::npos, "wallet detail missing full reference");
  require(detail.find("Transaction: txid-42") != std::string::npos, "wallet detail missing transaction id");
  require(detail.find("Local pending send was replaced by finalized chain activity.") != std::string::npos,
          "wallet detail missing chain explanation");
}

void test_wallet_window_confidential_detail_shows_reservation_gate() {
  finalis::wallet::WalletWindow window;
  require(window.history_view_ != nullptr, "wallet history table missing");
  require(window.activity_detail_title_label_ != nullptr, "wallet detail title missing");
  require(window.activity_detail_view_ != nullptr, "wallet detail view missing");

  finalis::Hash32 txid{};
  txid.fill(0x44);
  const finalis::OutPoint outpoint{txid, 2};
  window.tip_height_ = 101;
  window.confidential_coin_views_.clear();
  window.history_row_refs_.clear();
  window.pending_confidential_reservations_.clear();
  window.confidential_coin_views_.push_back(finalis::wallet::WalletWindow::ConfidentialCoinView{
      .outpoint = outpoint,
      .txid_hex = "4444444444444444444444444444444444444444444444444444444444444444",
      .vout = 2,
      .account_id = "acct-main",
      .amount = 500000000,
      .one_time_pubkey_hex = "02abcdef",
      .spent = false,
  });
  window.pending_confidential_reservations_[outpoint] = finalis::wallet::WalletStore::PendingSpend{
      .txid_hex = "pending-send-1",
      .inputs = {outpoint},
      .created_tip_height = 100,
      .created_unix_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch()),
  };
  window.history_row_refs_.push_back(
      finalis::wallet::WalletWindow::HistoryRowRef{finalis::wallet::WalletWindow::HistoryRowRef::Source::Confidential, 0});

  auto* table = window.history_view_;
  table->clearContents();
  table->setRowCount(1);
  table->setItem(0, 0, new QTableWidgetItem("Confidential Coin"));
  table->setItem(0, 1, new QTableWidgetItem("Pending (local)"));
  table->setItem(0, 2, new QTableWidgetItem("5 FLS"));
  table->setItem(0, 3, new QTableWidgetItem("coin-ref"));
  table->setItem(0, 4, new QTableWidgetItem("reserved"));
  table->setCurrentCell(0, 0);
  table->selectRow(0);
  QApplication::processEvents();
  window.update_selected_history_detail();

  const std::string title = window.activity_detail_title_label_->text().toStdString();
  const std::string detail = window.activity_detail_view_->toPlainText().toStdString();
  require(title.find("Reserved") != std::string::npos, "confidential detail title missing reserved state");
  require(detail.find("Reservation: Reserved. Release gate: tip +1/2") != std::string::npos,
          "confidential detail missing reservation gate");
}

void test_wallet_window_local_filter_preserves_rendered_ordering() {
  finalis::wallet::WalletWindow window;
  require(window.history_filter_combo_ != nullptr, "wallet history filter missing");
  require(window.history_view_ != nullptr, "wallet history table missing");
  require(window.activity_local_count_label_ != nullptr, "wallet local count chip missing");

  window.chain_records_.clear();
  window.mint_records_.clear();
  window.local_history_lines_.clear();
  window.history_row_refs_.clear();

  window.chain_records_.push_back(finalis::wallet::WalletWindow::ChainRecord{
      "FINALIZED", "SENT", "5 FLS", "chain-ref", "12", "txid-chain", "chain details",
  });
  window.local_history_lines_.push_back("[pending] relay accepted (pending-ref-1)");
  window.local_history_lines_.push_back("[finalized] pending send finalized (final-ref-2)");
  window.local_history_lines_.push_back("[info] pending send released (released-ref-3)");
  window.local_history_lines_.push_back("[onboarding] detached local tracking");

  window.history_filter_combo_->setCurrentText("Local");
  window.refresh_history_table();

  auto* table = window.history_view_;
  require(table->rowCount() == 4, "local history filter row count mismatch");
  require(table->item(0, 0)->text().toStdString() == "Local Send (local)", "local pending row type mismatch");
  require(table->item(0, 1)->text().toStdString() == "Pending (local)", "local pending row status mismatch");
  require(table->item(1, 0)->text().toStdString() == "Local Send (local)", "local finalized row type mismatch");
  require(table->item(1, 1)->text().toStdString() == "Finalized", "local finalized row status mismatch");
  require(table->item(2, 0)->text().toStdString() == "Local Event (local)", "local release row type mismatch");
  require(table->item(2, 1)->text().toStdString() == "Info", "local release row status mismatch");
  require(table->item(3, 0)->text().toStdString() == "Onboarding (local)", "local onboarding row type mismatch");
  require(table->item(3, 1)->text().toStdString() == "Info", "local onboarding row status mismatch");
  require(window.activity_local_count_label_->text().toStdString() == "Local: 4", "local count chip mismatch");
}

void test_advanced_page_onboarding_defaults() {
  finalis::wallet::AdvancedPage page;
  require(page.tab_widget() != nullptr, "advanced tabs missing");
  require(page.tab_widget()->count() == 4, "advanced tab count mismatch");
  require(page.tab_widget()->tabText(0).toStdString() == "Validator", "validator tab missing");

  auto* summary = page.validator_summary_label();
  require(summary != nullptr, "validator summary missing");
  require(summary->text().contains("node data folder"), "validator summary text mismatch");

  auto* state = page.validator_state_label();
  require(state != nullptr, "validator state label missing");
  require(state->text().toStdString() == "Not started", "validator state default mismatch");

  auto* action = page.validator_action_button();
  require(action != nullptr, "validator action button missing");
  require(action->text().toStdString() == "Start Validator Onboarding", "validator action button text mismatch");

  auto* details = page.validator_details_container();
  require(details != nullptr, "validator details container missing");
  require(!details->isVisible(), "validator details should start hidden");

  auto* adaptive = page.adaptive_regime_view();
  require(adaptive != nullptr, "adaptive regime diagnostics view missing");
  require(adaptive->toPlainText().contains("Adaptive checkpoint diagnostics unavailable."),
          "adaptive regime default text mismatch");
}

void test_wallet_window_adaptive_regime_diagnostics_render_current_status() {
  finalis::wallet::WalletWindow window;
  require(window.adaptive_regime_view_ != nullptr, "wallet adaptive regime diagnostics view missing");

  finalis::lightserver::RpcStatusView status;
  status.checkpoint_derivation_mode = std::string("fallback");
  status.checkpoint_fallback_reason = std::string("hysteresis_recovery_pending");
  status.fallback_sticky = true;
  status.qualified_depth = 26;
  status.adaptive_target_committee_size = 24;
  status.adaptive_min_eligible = 27;
  status.adaptive_min_bond = 15'000'000'000ULL;
  status.adaptive_slack = -1;
  status.target_expand_streak = 3;
  status.target_contract_streak = 0;
  status.fallback_rate_bps = 2500;
  status.sticky_fallback_rate_bps = 1250;
  status.fallback_rate_window_epochs = 8;
  status.near_threshold_operation = true;
  status.prolonged_expand_buildup = true;
  status.repeated_sticky_fallback = true;
  window.current_lightserver_status_ = status;

  window.update_connection_views();
  const std::string detail = window.adaptive_regime_view_->toPlainText().toStdString();
  require(detail.find("Checkpoint mode: fallback") != std::string::npos, "adaptive regime detail missing mode");
  require(detail.find("Checkpoint fallback reason: hysteresis_recovery_pending") != std::string::npos,
          "adaptive regime detail missing fallback reason");
  require(detail.find("Sticky fallback: yes") != std::string::npos, "adaptive regime detail missing sticky flag");
  require(detail.find("Qualified operator depth: 26") != std::string::npos, "adaptive regime detail missing qualified depth");
  require(detail.find("Adaptive committee target: 24") != std::string::npos, "adaptive regime detail missing target");
  require(detail.find("Adaptive eligible threshold: 27") != std::string::npos, "adaptive regime detail missing min eligible");
  require(detail.find("Adaptive bond floor: 150 FLS") != std::string::npos, "adaptive regime detail missing min bond");
  require(detail.find("Eligibility slack: -1") != std::string::npos, "adaptive regime detail missing slack");
  require(detail.find("Fallback rate: 25.00% over 8 epochs") != std::string::npos,
          "adaptive regime detail missing fallback rate");
  require(detail.find("- near-threshold-operation") != std::string::npos, "adaptive regime detail missing threshold flag");
  require(detail.find("- prolonged-expand-buildup") != std::string::npos,
          "adaptive regime detail missing expand flag");
  require(detail.find("- repeated-sticky-fallback") != std::string::npos,
          "adaptive regime detail missing sticky fallback flag");
}

void test_wallet_window_onboarding_badge_states() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.clear();

  finalis::wallet::WalletWindow window;
  require(window.validator_state_label_ != nullptr, "wallet validator state label missing");

  window.update_validator_onboarding_view();
  require(window.validator_state_label_->text().contains("IDLE"), "wallet onboarding state missing idle badge");
  require(window.validator_state_label_->text().contains("Not started"), "wallet onboarding state missing idle text");

  settings.setValue("validator/last_txid", "abcd1234");
  settings.setValue("validator/detached_local", false);
  settings.sync();
  window.update_validator_onboarding_view();
  require(window.validator_state_label_->text().contains("TRACKED"), "wallet onboarding state missing tracked badge");

  settings.setValue("validator/detached_local", true);
  settings.sync();
  window.update_validator_onboarding_view();
  require(window.validator_state_label_->text().contains("DETACHED"), "wallet onboarding state missing detached badge");
}

void test_wallet_window_defaults_to_lightserver_rpc_port() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.clear();
  settings.sync();

  finalis::wallet::WalletWindow window;
  const auto endpoints = window.configured_lightserver_endpoints();
  require(endpoints.size() == 1, "wallet default endpoint count mismatch");
  require(endpoints.front().toStdString() == "http://127.0.0.1:19444/rpc",
          std::string("wallet default endpoint mismatch: ") + endpoints.front().toStdString());
}

void test_wallet_history_flow_classification_uses_net_wallet_effect() {
  auto received = finalis::wallet::classify_wallet_history_flow(100000000ULL, 0);
  require(received.kind.toStdString() == "received", "received classification kind mismatch");
  require(received.detail.toStdString() == "1 FLS", "received classification detail mismatch");

  auto sent = finalis::wallet::classify_wallet_history_flow(0, 50000000ULL);
  require(sent.kind.toStdString() == "sent", "sent classification kind mismatch");
  require(sent.detail.toStdString() == "0.5 FLS", "sent classification detail mismatch");

  auto self_transfer = finalis::wallet::classify_wallet_history_flow(100000000ULL, 100000000ULL);
  require(self_transfer.kind.toStdString() == "activity", "self-transfer classification kind mismatch");
  require(self_transfer.detail.toStdString() == "self-transfer", "self-transfer classification detail mismatch");

  auto net_sent = finalis::wallet::classify_wallet_history_flow(100000000ULL, 250000000ULL);
  require(net_sent.kind.toStdString() == "sent", "net-sent classification kind mismatch");
  require(net_sent.detail.toStdString() == "1.5 FLS net", "net-sent classification detail mismatch");
}

void test_onboarding_failed_state_wording_contract() {
  const QString failed = finalis::wallet::onboarding_error_display_text(
      "tx_missing_or_unconfirmed_input", "fallback should not be used");
  require(failed.contains("selected finalized inputs changed before broadcast"),
          "failed onboarding wording mismatch for input-change case");

  const QString rejected = finalis::wallet::onboarding_error_display_text(
      "tx_rejected", "fallback should not be used");
  require(rejected.contains("rejected by the relay/runtime checks"),
          "failed onboarding wording mismatch for rejected tx case");

  const QString generic = finalis::wallet::onboarding_error_display_text(
      "", "Custom operator-facing fallback");
  require(generic == "Custom operator-facing fallback",
          "failed onboarding fallback wording mismatch");
}

}  // namespace

int main(int argc, char** argv) {
  char settings_dir_template[] = "/tmp/finalis-widget-tests-XXXXXX";
  char* settings_dir = mkdtemp(settings_dir_template);
  if (!settings_dir) {
    std::cerr << "failed to create settings temp dir\n";
    return 1;
  }
  qputenv("XDG_CONFIG_HOME", QByteArray(settings_dir));
  qputenv("QT_QPA_PLATFORM", QByteArray("offscreen"));
  QApplication app(argc, argv);
  try {
  test_activity_page_local_filter_and_chips();
  test_wallet_window_history_selection_updates_detail_panel();
  test_wallet_window_confidential_detail_shows_reservation_gate();
  test_wallet_window_local_filter_preserves_rendered_ordering();
    test_advanced_page_onboarding_defaults();
    test_wallet_window_adaptive_regime_diagnostics_render_current_status();
    test_wallet_window_onboarding_badge_states();
    test_wallet_window_defaults_to_lightserver_rpc_port();
    test_wallet_history_flow_classification_uses_net_wallet_effect();
    test_onboarding_failed_state_wording_contract();
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
  std::cout << "all widget tests passed\n";
  return 0;
}

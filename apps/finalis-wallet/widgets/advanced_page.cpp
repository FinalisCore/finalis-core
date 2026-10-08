// SPDX-License-Identifier: MIT

#include "advanced_page.hpp"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QVariant>
#include <QVBoxLayout>

namespace finalis::wallet {
namespace {

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
}

void configure_form_layout(QFormLayout* layout) {
  if (!layout) return;
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setHorizontalSpacing(14);
  layout->setVerticalSpacing(10);
  layout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
  layout->setFormAlignment(Qt::AlignTop | Qt::AlignLeft);
  layout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
}

void configure_table(QTableWidget* table, const QStringList& headers) {
  table->setColumnCount(headers.size());
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setAlternatingRowColors(true);
  table->setSortingEnabled(true);
  table->verticalHeader()->setVisible(false);
  table->horizontalHeader()->setStretchLastSection(true);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  table->horizontalHeader()->setMinimumSectionSize(90);
}

QScrollArea* wrap_scroll(QWidget* content, QWidget* parent) {
  auto* scroll = new QScrollArea(parent);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setWidget(content);
  return scroll;
}

}  // namespace

AdvancedPage::AdvancedPage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* intro = new QLabel(
      "Advanced is for operator and power-user workflows. It keeps validator tools, privacy flows, service configuration, and runtime inspection available without crowding the main wallet screens.",
      this);
  intro->setWordWrap(true);
  intro->setProperty("role", QVariant(QStringLiteral("muted")));

  tabs_ = new QTabWidget(this);
  tabs_->setDocumentMode(true);
  root->addWidget(intro);
  root->addWidget(tabs_);

  auto* validator = new QWidget(this);
  auto* validator_layout = new QVBoxLayout(validator);
  configure_page_layout(validator_layout);
  auto* validator_intro = new QLabel(
      "Validator onboarding is for operators running a local node. Configure your node data folder, validator key, and local RPC endpoint once, then start onboarding from this screen.",
      validator);
  validator_intro->setWordWrap(true);
  validator_intro->setProperty("role", QVariant(QStringLiteral("muted")));
  validator_layout->addWidget(validator_intro);

  auto* validator_register_box = new QGroupBox("Register Validator", validator);
  validator_register_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  auto* validator_register_layout = new QVBoxLayout(validator_register_box);
  validator_register_layout->setSpacing(12);

  auto* validator_register_intro = new QLabel(
      "One-click registration uses finalized spendable coins only. The wallet checks operator readiness, reserves the bond, builds the join transaction, submits it, and tracks finalization and activation.",
      validator_register_box);
  validator_register_intro->setWordWrap(true);
  validator_register_intro->setProperty("role", QVariant(QStringLiteral("muted")));
  validator_register_layout->addWidget(validator_register_intro);

  auto* validator_summary_grid = new QGridLayout();
  validator_summary_grid->setHorizontalSpacing(14);
  validator_summary_grid->setVerticalSpacing(10);
  validator_summary_grid->setColumnStretch(1, 1);
  validator_summary_grid->addWidget(new QLabel("Required bond", validator_register_box), 0, 0);
  validator_required_bond_label_ = new QLabel("Not checked", validator_register_box);
  validator_required_bond_label_->setWordWrap(true);
  validator_summary_grid->addWidget(validator_required_bond_label_, 0, 1);
  validator_summary_grid->addWidget(new QLabel("Available finalized balance", validator_register_box), 1, 0);
  validator_available_balance_label_ = new QLabel("Not checked", validator_register_box);
  validator_available_balance_label_->setWordWrap(true);
  validator_summary_grid->addWidget(validator_available_balance_label_, 1, 1);
  validator_summary_grid->addWidget(new QLabel("Readiness blockers", validator_register_box), 2, 0);
  validator_blockers_label_ = new QLabel("Not checked", validator_register_box);
  validator_blockers_label_->setWordWrap(true);
  validator_summary_grid->addWidget(validator_blockers_label_, 2, 1);
  validator_summary_grid->addWidget(new QLabel("Live tx / finalization status", validator_register_box), 3, 0);
  validator_live_status_label_ = new QLabel("No registration tracked yet", validator_register_box);
  validator_live_status_label_->setWordWrap(true);
  validator_summary_grid->addWidget(validator_live_status_label_, 3, 1);
  validator_register_layout->addLayout(validator_summary_grid);

  auto* validator_actions = new QHBoxLayout();
  validator_actions->setSpacing(8);
  validator_action_button_ = new QPushButton("Register Validator", validator_register_box);
  validator_refresh_button_ = new QPushButton("Refresh Status", validator_register_box);
  validator_cancel_button_ = new QPushButton("Cancel Registration", validator_register_box);
  validator_toggle_details_button_ = new QPushButton("Show Details", validator_register_box);
  validator_actions->addWidget(validator_action_button_);
  validator_actions->addWidget(validator_refresh_button_);
  validator_actions->addWidget(validator_cancel_button_);
  validator_actions->addStretch(1);
  validator_actions->addWidget(validator_toggle_details_button_);
  validator_register_layout->addLayout(validator_actions);

  validator_layout->addWidget(validator_register_box);

  auto* validator_box = new QGroupBox("Validator Setup", validator);
  validator_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  auto* validator_layout_box = new QVBoxLayout(validator_box);
  validator_layout_box->setSpacing(12);

  auto* validator_config_form = new QFormLayout();
  configure_form_layout(validator_config_form);

  auto* db_row = new QWidget(validator_box);
  auto* db_row_layout = new QHBoxLayout(db_row);
  db_row_layout->setContentsMargins(0, 0, 0, 0);
  db_row_layout->setSpacing(8);
  validator_db_path_edit_ = new QLineEdit(db_row);
  validator_db_path_edit_->setPlaceholderText("Select your node data folder");
  validator_db_browse_button_ = new QPushButton("Browse…", db_row);
  db_row_layout->addWidget(validator_db_path_edit_, 1);
  db_row_layout->addWidget(validator_db_browse_button_);
  validator_config_form->addRow("Node DB Path", db_row);

  auto* key_row = new QWidget(validator_box);
  auto* key_row_layout = new QHBoxLayout(key_row);
  key_row_layout->setContentsMargins(0, 0, 0, 0);
  key_row_layout->setSpacing(8);
  validator_key_path_edit_ = new QLineEdit(key_row);
  validator_key_path_edit_->setPlaceholderText("Select your validator key file");
  validator_key_browse_button_ = new QPushButton("Browse…", key_row);
  key_row_layout->addWidget(validator_key_path_edit_, 1);
  key_row_layout->addWidget(validator_key_browse_button_);
  validator_config_form->addRow("Validator Key Path", key_row);

  validator_rpc_url_edit_ = new QLineEdit(validator_box);
  validator_rpc_url_edit_->setPlaceholderText("http://127.0.0.1:19444/rpc");
  validator_config_form->addRow("RPC Endpoint", validator_rpc_url_edit_);

  validator_layout_box->addLayout(validator_config_form);

  validator_summary_label_ = new QLabel("Set your node data folder, validator key, and local RPC endpoint.", validator_box);
  validator_summary_label_->setWordWrap(true);
  validator_layout_box->addWidget(validator_summary_label_);

  auto* validator_grid = new QGridLayout();
  validator_grid->setHorizontalSpacing(14);
  validator_grid->setVerticalSpacing(10);
  validator_grid->setColumnStretch(1, 1);
  validator_grid->addWidget(new QLabel("Readiness", validator_box), 0, 0);
  validator_readiness_label_ = new QLabel("Not checked", validator_box);
  validator_readiness_label_->setWordWrap(true);
  validator_grid->addWidget(validator_readiness_label_, 0, 1);
  validator_grid->addWidget(new QLabel("Funding", validator_box), 1, 0);
  validator_funding_label_ = new QLabel("Not checked", validator_box);
  validator_funding_label_->setWordWrap(true);
  validator_grid->addWidget(validator_funding_label_, 1, 1);
  validator_grid->addWidget(new QLabel("Registration Status", validator_box), 2, 0);
  validator_state_label_ = new QLabel("Not started", validator_box);
  validator_state_label_->setWordWrap(true);
  validator_grid->addWidget(validator_state_label_, 2, 1);
  validator_layout_box->addLayout(validator_grid);

  validator_details_container_ = new QWidget(validator_box);
  auto* validator_details_layout = new QVBoxLayout(validator_details_container_);
  validator_details_layout->setContentsMargins(0, 0, 0, 0);
  validator_details_layout->setSpacing(8);
  auto* validator_details_title =
      new QLabel("Advanced Details", validator_details_container_);
  validator_details_view_ = new QTextEdit(validator_details_container_);
  validator_details_view_->setReadOnly(true);
  validator_details_view_->setLineWrapMode(QTextEdit::NoWrap);
  validator_details_view_->setMinimumHeight(140);
  validator_details_view_->setPlainText("No validator details yet.");
  validator_details_layout->addWidget(validator_details_title);
  validator_details_layout->addWidget(validator_details_view_);
  validator_details_container_->setVisible(false);
  validator_layout_box->addWidget(validator_details_container_);

  validator_layout->addWidget(validator_box);
  auto* validator_note = new QLabel(
      "This keeps the existing onboarding protocol and validator rules unchanged. It only makes the operator flow explicit and easier to drive from the wallet.",
      validator);
  validator_note->setWordWrap(true);
  validator_note->setProperty("role", QVariant(QStringLiteral("muted")));
  validator_layout->addWidget(validator_note);
  validator_layout->addStretch(1);
  tabs_->addTab(wrap_scroll(validator, this), "Validator");

  auto* connections = new QWidget(this);
  auto* connections_layout = new QVBoxLayout(connections);
  configure_page_layout(connections_layout);
  auto* connections_intro = new QLabel(
      "Connections controls where the wallet reads finalized state. Edit service endpoints here.",
      connections);
  connections_intro->setWordWrap(true);
  connections_intro->setProperty("role", QVariant(QStringLiteral("muted")));
  connections_layout->addWidget(connections_intro);

  auto* settings_box = new QGroupBox("Service Endpoints", connections);
  auto* settings_form = new QFormLayout(settings_box);
  configure_form_layout(settings_form);
  lightserver_urls_edit_ = new QTextEdit(settings_box);
  lightserver_urls_edit_->setAcceptRichText(false);
  lightserver_urls_edit_->setLineWrapMode(QTextEdit::NoWrap);
  lightserver_urls_edit_->setPlaceholderText("http://127.0.0.1:8080/rpc\nhttp://127.0.0.1:8081/rpc");
  lightserver_urls_edit_->setMinimumHeight(96);
  pin_lightserver_endpoint_checkbox_ = new QCheckBox("Always try the first endpoint first", settings_box);
  settings_form->addRow("Finalized-state RPC endpoints", lightserver_urls_edit_);
  settings_form->addRow("", pin_lightserver_endpoint_checkbox_);
  save_settings_button_ = new QPushButton("Save Connection Settings", settings_box);
  settings_form->addRow("", save_settings_button_);
  connections_layout->addWidget(settings_box);

  auto* summary_box = new QGroupBox("Current Runtime Summary", connections);
  auto* summary_layout = new QVBoxLayout(summary_box);
  connection_summary_label_ = new QLabel(summary_box);
  connection_summary_label_->setWordWrap(true);
  connection_summary_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  summary_layout->addWidget(connection_summary_label_);
  connections_layout->addWidget(summary_box);

  auto* note = new QLabel(
      "Changing these settings affects how the wallet refreshes finalized data. "
      "It does not change consensus rules or make pending network activity visible.",
      connections);
  note->setWordWrap(true);
  note->setProperty("role", QVariant(QStringLiteral("muted")));
  connections_layout->addWidget(note);
  connections_layout->addStretch(1);
  tabs_->addTab(wrap_scroll(connections, this), "Connections");

  auto* diagnostics = new QWidget(this);
  auto* diagnostics_layout = new QVBoxLayout(diagnostics);
  configure_page_layout(diagnostics_layout);
  auto* diagnostics_intro = new QLabel(
      "Diagnostics is read-only. Use it to inspect cross-check results and runtime disagreement signals across configured endpoints.",
      diagnostics);
  diagnostics_intro->setWordWrap(true);
  diagnostics_intro->setProperty("role", QVariant(QStringLiteral("muted")));
  diagnostics_layout->addWidget(diagnostics_intro);
  auto* crosscheck_box = new QGroupBox("Endpoint Cross-Check", diagnostics);
  auto* crosscheck_layout = new QVBoxLayout(crosscheck_box);
  crosscheck_detail_view_ = new QTextEdit(crosscheck_box);
  crosscheck_detail_view_->setReadOnly(true);
  crosscheck_detail_view_->setLineWrapMode(QTextEdit::NoWrap);
  crosscheck_detail_view_->setMinimumHeight(160);
  crosscheck_detail_view_->setPlainText("No endpoint cross-check yet.");
  crosscheck_layout->addWidget(crosscheck_detail_view_);
  diagnostics_layout->addWidget(crosscheck_box);
  auto* adaptive_box = new QGroupBox("Adaptive Regime Diagnostics", diagnostics);
  auto* adaptive_layout = new QVBoxLayout(adaptive_box);
  adaptive_regime_view_ = new QTextEdit(adaptive_box);
  adaptive_regime_view_->setReadOnly(true);
  adaptive_regime_view_->setLineWrapMode(QTextEdit::NoWrap);
  adaptive_regime_view_->setMinimumHeight(220);
  adaptive_regime_view_->setPlainText("Adaptive checkpoint diagnostics unavailable.");
  adaptive_layout->addWidget(adaptive_regime_view_);
  diagnostics_layout->addWidget(adaptive_box);
  auto* diagnostics_note = new QLabel(
      "Cross-check and adaptive regime diagnostics are informational only. They help operators inspect finalized checkpoint pressure and endpoint consistency, but they do not change consensus behavior.",
      diagnostics);
  diagnostics_note->setWordWrap(true);
  diagnostics_note->setProperty("role", QVariant(QStringLiteral("muted")));
  diagnostics_layout->addWidget(diagnostics_note);
  diagnostics_layout->addStretch(1);
  tabs_->addTab(wrap_scroll(diagnostics, this), "Diagnostics");
}

}  // namespace finalis::wallet

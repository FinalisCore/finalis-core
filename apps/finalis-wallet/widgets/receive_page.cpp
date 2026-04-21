// SPDX-License-Identifier: MIT

#include "receive_page.hpp"

#include <QAbstractItemView>
#include <QFont>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QTextEdit>
#include <QHeaderView>
#include <QVariant>
#include <QVBoxLayout>

namespace finalis::wallet {
namespace {

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
}

void configure_table(QTableWidget* table, const QStringList& headers) {
  table->setColumnCount(headers.size());
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setAlternatingRowColors(true);
  table->setSortingEnabled(false);
  table->verticalHeader()->setVisible(false);
  table->horizontalHeader()->setStretchLastSection(true);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
}

}  // namespace

ReceivePage::ReceivePage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto* content = new QWidget(scroll);
  auto* layout = new QVBoxLayout(content);
  configure_page_layout(layout);

  heading_label_ = new QLabel("Receive FLS", this);
  QFont heading_font = heading_label_->font();
  heading_font.setPointSize(18);
  heading_font.setBold(true);
  heading_label_->setFont(heading_font);
  layout->addWidget(heading_label_);

  auto* intro = new QLabel(
      "Use this address for standard on-chain incoming transfers. The wallet shows incoming activity after it reaches finalized state.",
      this);
  intro->setWordWrap(true);
  intro->setProperty("role", QVariant(QStringLiteral("muted")));
  layout->addWidget(intro);

  auto* box = new QGroupBox("Primary Receive Address", this);
  auto* box_layout = new QVBoxLayout(box);
  box_layout->setSpacing(12);
  address_label_ = new QLabel("-", box);
  address_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  address_label_->setWordWrap(true);
  QFont address_font = address_label_->font();
  address_font.setPointSize(13);
  address_font.setBold(true);
  address_label_->setFont(address_font);
  box_layout->addWidget(address_label_);

  auto* action_row = new QHBoxLayout();
  action_row->setSpacing(8);
  copy_button_ = new QPushButton("Copy Receive Address", box);
  copy_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  copy_status_label_ = new QLabel("Address ready to share.", box);
  copy_status_label_->setWordWrap(true);
  copy_status_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  action_row->addWidget(copy_button_);
  action_row->addWidget(copy_status_label_, 1);
  box_layout->addLayout(action_row);

  finalized_note_label_ = new QLabel(
      "Only finalized incoming transfers appear in wallet balances and activity. Pending network gossip is not shown here.",
      box);
  finalized_note_label_->setWordWrap(true);
  finalized_note_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  box_layout->addWidget(finalized_note_label_);

  layout->addWidget(box, 0, Qt::AlignLeft | Qt::AlignTop);

  auto* confidential_box = new QGroupBox("Confidential Receive", this);
  auto* confidential_layout = new QVBoxLayout(confidential_box);
  confidential_layout->setSpacing(12);
  confidential_address_label_ = new QLabel("not configured", confidential_box);
  confidential_address_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  confidential_address_label_->setWordWrap(true);
  QFont confidential_font = confidential_address_label_->font();
  confidential_font.setPointSize(12);
  confidential_font.setBold(true);
  confidential_address_label_->setFont(confidential_font);
  confidential_layout->addWidget(confidential_address_label_);

  auto* confidential_account_actions = new QHBoxLayout();
  confidential_account_actions->setSpacing(8);
  create_confidential_account_button_ = new QPushButton("New Confidential Account", confidential_box);
  import_confidential_account_button_ = new QPushButton("Import Confidential Account", confidential_box);
  confidential_account_actions->addWidget(create_confidential_account_button_);
  confidential_account_actions->addWidget(import_confidential_account_button_);
  confidential_account_actions->addStretch(1);
  confidential_layout->addLayout(confidential_account_actions);

  auto* confidential_request_title = new QLabel("Shareable confidential request", confidential_box);
  confidential_request_title->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_layout->addWidget(confidential_request_title);

  confidential_request_label_ = new QLabel("not generated", confidential_box);
  confidential_request_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  confidential_request_label_->setWordWrap(true);
  confidential_request_label_->setFont(confidential_font);
  confidential_layout->addWidget(confidential_request_label_);

  confidential_request_summary_label_ = new QLabel("Outstanding requests: 0 · Consumed: 0", confidential_box);
  confidential_request_summary_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_layout->addWidget(confidential_request_summary_label_);

  confidential_requests_table_ = new QTableWidget(confidential_box);
  confidential_requests_table_->setMinimumHeight(140);
  configure_table(confidential_requests_table_, {"Status", "Account", "Request ID", "Scan Tag", "One-Time Key"});
  confidential_layout->addWidget(confidential_requests_table_);

  auto* confidential_actions = new QHBoxLayout();
  confidential_actions->setSpacing(8);
  generate_confidential_request_button_ = new QPushButton("Generate Request", confidential_box);
  copy_confidential_request_button_ = new QPushButton("Copy Request", confidential_box);
  import_confidential_tx_button_ = new QPushButton("Import Received Tx", confidential_box);
  confidential_actions->addWidget(generate_confidential_request_button_);
  confidential_actions->addWidget(copy_confidential_request_button_);
  confidential_actions->addWidget(import_confidential_tx_button_);
  confidential_actions->addStretch(1);
  confidential_layout->addLayout(confidential_actions);

  confidential_coin_summary_label_ = new QLabel("Imported confidential coins: 0", confidential_box);
  confidential_coin_summary_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_layout->addWidget(confidential_coin_summary_label_);

  confidential_coins_table_ = new QTableWidget(confidential_box);
  confidential_coins_table_->setMinimumHeight(160);
  configure_table(confidential_coins_table_, {"Status", "Amount", "Outpoint", "Account", "One-Time Key", "Reservation"});
  confidential_layout->addWidget(confidential_coins_table_);

  auto* confidential_coin_actions = new QHBoxLayout();
  confidential_coin_actions->setSpacing(8);
  copy_confidential_pending_txid_button_ = new QPushButton("Copy Pending Txid", confidential_box);
  copy_confidential_pending_txid_button_->setEnabled(false);
  inspect_confidential_pending_tx_button_ = new QPushButton("Inspect Pending Tx", confidential_box);
  inspect_confidential_pending_tx_button_->setEnabled(false);
  confidential_coin_actions->addWidget(copy_confidential_pending_txid_button_);
  confidential_coin_actions->addWidget(inspect_confidential_pending_tx_button_);
  confidential_coin_actions->addStretch(1);
  confidential_layout->addLayout(confidential_coin_actions);

  auto* confidential_pending_status_title = new QLabel("Selected pending tx status", confidential_box);
  confidential_pending_status_title->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_layout->addWidget(confidential_pending_status_title);

  confidential_pending_status_view_ = new QTextEdit(confidential_box);
  confidential_pending_status_view_->setReadOnly(true);
  confidential_pending_status_view_->setMinimumHeight(120);
  confidential_pending_status_view_->setPlainText(
      "Select a reserved confidential coin to inspect the current pending transaction status.");
  confidential_layout->addWidget(confidential_pending_status_view_);

  confidential_note_label_ = new QLabel(
      "Confidential receive requires a configured stealth account and encrypted local recovery material. "
      "This wallet will not advertise a confidential address until that state exists locally. Use Generate Request to produce a one-time shareable request URI for supported TxV2 sends.",
      confidential_box);
  confidential_note_label_->setWordWrap(true);
  confidential_note_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_layout->addWidget(confidential_note_label_);
  layout->addWidget(confidential_box, 0, Qt::AlignLeft | Qt::AlignTop);

  auto* help_box = new QGroupBox("What This Screen Covers", this);
  auto* help_layout = new QVBoxLayout(help_box);
  help_layout->setSpacing(8);
  auto* help = new QLabel(
      "This screen is intentionally narrow: it gives you the current wallet address and receive guidance. "
      "Connection setup, mint workflows, and validator tools stay under Advanced.",
      help_box);
  help->setWordWrap(true);
  help->setProperty("role", QVariant(QStringLiteral("muted")));
  help_layout->addWidget(help);
  layout->addWidget(help_box, 0, Qt::AlignLeft | Qt::AlignTop);
  layout->addStretch(1);

  scroll->setWidget(content);
  root->addWidget(scroll);
}

}  // namespace finalis::wallet

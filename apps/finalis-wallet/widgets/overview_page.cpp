// SPDX-License-Identifier: MIT

#include "overview_page.hpp"

#include <QAbstractItemView>
#include <QFont>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QSizePolicy>
#include <QTableWidget>
#include <QTableWidgetItem>
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

OverviewPage::OverviewPage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto* content = new QWidget(scroll);
  auto* layout = new QVBoxLayout(content);
  configure_page_layout(layout);

  auto* top_row = new QVBoxLayout();
  top_row->setSpacing(12);

  auto* balance_box = new QGroupBox("Wallet", this);
  balance_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  auto* balance_layout = new QVBoxLayout(balance_box);
  balance_layout->setSpacing(10);
  auto* balance_caption = new QLabel("Available balance", balance_box);
  balance_caption->setProperty("role", QVariant(QStringLiteral("muted")));
  balance_label_ = new QLabel("0 FLS", balance_box);
  QFont balance_font = balance_label_->font();
  balance_font.setPointSize(24);
  balance_font.setBold(true);
  balance_label_->setFont(balance_font);
  pending_balance_label_ = new QLabel("Pending outgoing: 0 FLS", balance_box);
  pending_balance_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  confidential_balance_label_ = new QLabel("Confidential balance: unavailable", balance_box);
  confidential_balance_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  auto* action_row = new QHBoxLayout();
  action_row->setSpacing(8);
  send_button_ = new QPushButton("Send", balance_box);
  receive_button_ = new QPushButton("Receive", balance_box);
  view_activity_button_ = new QPushButton("View Activity", balance_box);
  open_explorer_button_ = new QPushButton("Open Explorer", balance_box);
  send_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  receive_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  view_activity_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  open_explorer_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  action_row->addWidget(send_button_);
  action_row->addWidget(receive_button_);
  action_row->addWidget(view_activity_button_);
  action_row->addWidget(open_explorer_button_);
  action_row->addStretch(1);
  balance_layout->addWidget(balance_caption);
  balance_layout->addWidget(balance_label_);
  balance_layout->addWidget(pending_balance_label_);
  balance_layout->addWidget(confidential_balance_label_);
  balance_layout->addLayout(action_row);
  top_row->addWidget(balance_box);

  auto* status_box = new QGroupBox("Finalized Status", this);
  status_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  auto* status_grid = new QGridLayout(status_box);
  status_grid->setHorizontalSpacing(14);
  status_grid->setVerticalSpacing(10);
  status_grid->setColumnStretch(1, 1);
  status_grid->addWidget(new QLabel("Wallet:", status_box), 0, 0);
  wallet_status_label_ = new QLabel("No wallet open", status_box);
  wallet_status_label_->setWordWrap(true);
  status_grid->addWidget(wallet_status_label_, 0, 1);
  status_grid->addWidget(new QLabel("Network:", status_box), 1, 0);
  network_label_ = new QLabel("mainnet", status_box);
  network_label_->setWordWrap(true);
  status_grid->addWidget(network_label_, 1, 1);
  status_grid->addWidget(new QLabel("Finalized tip:", status_box), 2, 0);
  tip_status_label_ = new QLabel("-", status_box);
  tip_status_label_->setWordWrap(true);
  status_grid->addWidget(tip_status_label_, 2, 1);
  status_grid->addWidget(new QLabel("Connection:", status_box), 3, 0);
  connection_status_label_ = new QLabel("No healthy endpoint", status_box);
  connection_status_label_->setWordWrap(true);
  status_grid->addWidget(connection_status_label_, 3, 1);
  top_row->addWidget(status_box);
  layout->addLayout(top_row);

  auto* identity_box = new QGroupBox("Wallet Identity", this);
  identity_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  auto* summary_grid = new QGridLayout(identity_box);
  summary_grid->setHorizontalSpacing(14);
  summary_grid->setVerticalSpacing(10);
  summary_grid->setColumnStretch(1, 1);
  summary_grid->addWidget(new QLabel("Wallet file:", identity_box), 0, 0);
  wallet_file_label_ = new QLabel("-", identity_box);
  wallet_file_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  wallet_file_label_->setWordWrap(true);
  summary_grid->addWidget(wallet_file_label_, 0, 1);
  summary_grid->addWidget(new QLabel("Primary address:", identity_box), 1, 0);
  receive_address_label_ = new QLabel("-", identity_box);
  receive_address_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  receive_address_label_->setWordWrap(true);
  summary_grid->addWidget(receive_address_label_, 1, 1);
  summary_grid->addWidget(new QLabel("Confidential receive:", identity_box), 2, 0);
  confidential_receive_label_ = new QLabel("not configured", identity_box);
  confidential_receive_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  confidential_receive_label_->setWordWrap(true);
  summary_grid->addWidget(confidential_receive_label_, 2, 1);
  layout->addWidget(identity_box);

  auto* activity_box = new QGroupBox("Recent Activity", this);
  auto* activity_layout = new QVBoxLayout(activity_box);
  activity_layout->setSpacing(8);
  activity_preview_table_ = new QTableWidget(activity_box);
  activity_preview_table_->setMinimumHeight(140);
  configure_table(activity_preview_table_, {"Status", "Activity", "State"});
  activity_layout->addWidget(activity_preview_table_);
  layout->addWidget(activity_box);

  auto* note = new QLabel(
      "Overview stays focused on balance, wallet identity, finalized status, and recent activity. "
      "Validator, mint, and diagnostics remain under Advanced.",
      this);
  note->setWordWrap(true);
  note->setProperty("role", QVariant(QStringLiteral("muted")));
  layout->addWidget(note);
  layout->addStretch(1);

  scroll->setWidget(content);
  root->addWidget(scroll);
}

}  // namespace finalis::wallet

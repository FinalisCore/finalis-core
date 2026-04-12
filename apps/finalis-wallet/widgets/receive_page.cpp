#include "receive_page.hpp"

#include <QFont>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVariant>
#include <QVBoxLayout>

namespace finalis::wallet {
namespace {

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
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

  confidential_note_label_ = new QLabel(
      "Confidential receive requires a configured stealth account and encrypted local recovery material. "
      "This wallet will not advertise a confidential address until that state exists locally.",
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
